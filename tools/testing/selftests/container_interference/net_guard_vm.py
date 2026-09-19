#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Native high-rate private Socket operations, with no guard threshold changes."""
import json
import os
from pathlib import Path
import socket
import subprocess
import time
from types import SimpleNamespace
import prototype_admission
from session import source_manifest
from source_switches import observe
from net_fixture_check import case_order
from net_guard_check import check


def run():
    os.umask(0o077); os.sched_setaffinity(0,{7})
    env=prototype_admission.environment(); prototype_admission.check_environment(env)
    if Path('/sys/module/cis_observe/parameters/net_shift').read_text().strip()!='0':
        raise ValueError('frozen full-rate source required')
    out=Path('/tmp/net-evidence'); out.mkdir(mode=0o700)
    root=Path('/sys/fs/cgroup/cis-net-guard'); root.mkdir(); (root/'management').mkdir()
    (root/'management/cgroup.procs').write_text(str(os.getpid()))
    (root/'cgroup.subtree_control').write_text('+cpu +memory +cpuset')
    roots=[]
    for i in range(2):
        p=root/('root%d'%i); p.mkdir(); (p/'memory.max').write_text(str(64<<20)); roots.append(p)
    args=SimpleNamespace(worker='/profile/session-worker',residue='/profile/session-residue',bpf='/profile/cis.bpf.o')
    source=source_manifest(args,env['boot_id']); permit=prototype_admission.create(source,env,time.monotonic_ns())
    plan=dict(schema='cis-net-guard-v1',order=case_order(('storm',)),rounds=3,seconds=4,
              buckets=8,bucket_ns=500000000,window_ms=2000,entry_rate_limit=200000,roots=2,
              cpu=[0,1],management_cpu=7,net_shift=0,sockets_per_actor=1,hold_ms=0)
    for name,data in (('plan',plan),('permit',permit)): (out/(name+'.json')).write_text(json.dumps(data,indent=2))
    endpoint='/run/cis-net-guard.sock'; log=(out/'controller.log').open('x'); audit=(out/'requests.jsonl').open('x')
    daemon=subprocess.Popen(['/usr/bin/python3','/profile/session.py','--socket',endpoint,'--directory',str(out/'records'),
        '--worker',args.worker,'--residue',args.residue,'--bpf',args.bpf,'--admission-policy','prototype',
        '--prototype-permit',str(out/'permit.json'),'daemon'],stdout=log,stderr=log)
    children=[]; handles=[]; results=[]

    def request(op,**fields):
        before=time.monotonic_ns(); req=dict(version=1,op=op,**fields)
        with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as sock:
            sock.settimeout(15); sock.connect(endpoint); sock.send(json.dumps(req).encode()); reply=json.loads(sock.recv(8192))
        audit.write(json.dumps(dict(before_ns=before,after_ns=time.monotonic_ns(),request=req,response=reply))+'\n'); audit.flush()
        if not reply['ok']: raise RuntimeError(reply)
        return reply['data']

    def wait(sid,field):
        deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            r=request('status',session=sid)
            if r.get(field): return r
            if r.get('finalized'): raise RuntimeError(r)
            time.sleep(.02)
        raise TimeoutError(sid)

    def snapshot():
        return dict(time_ns=time.monotonic_ns(),source_audit=Path('/sys/kernel/debug/cis_net_audit').read_text(),
                    proc_stat=Path('/proc/stat').read_text(),memory=Path('/proc/meminfo').read_text(),
                    roots=[{k:(p/k).read_text() for k in ('cpu.stat','memory.current','memory.peak','memory.events')} for p in roots])

    try:
        deadline=time.monotonic()+10
        while not Path(endpoint).exists():
            if daemon.poll() is not None or time.monotonic()>deadline: raise RuntimeError('daemon readiness')
            time.sleep(.02)
        targets=[request('register',path=str(p))['target'] for p in roots]
        for label in plan['order']:
            collecting='-net' in label; sid=None; before=snapshot()
            if collecting:
                sid=request('start',collector='net',targets=targets,nonce=label.replace('-',''),window_ms=2000)['session_id']
                window=wait(sid,'window')['window']; active=observe('net')
                start=max(window['start_ns']+100000000,time.monotonic_ns()+100000000)
            else:
                active=observe(None); start=time.monotonic_ns()+300000000
            running=[]
            for i,p in enumerate(roots):
                handle=(out/(label+'-%d.log'%i)).open('x'); handles.append(handle)
                child=subprocess.Popen(['/session_launch',str(p),str(i),'/net_storm_workload',str(i),str(start)],stdout=handle,stderr=handle)
                running.append(child); children.append(child)
            if sid: wait(sid,'finalized')
            idle=observe(None); detached=snapshot()
            codes=[p.wait(timeout=10) for p in running]; after=snapshot()
            record=json.loads((out/'records'/(sid+'.json')).read_text()) if sid else None
            raw=(out/'records'/(sid+'.jsonl')).read_bytes() if sid else None
            evidence=dict(label=label,session_id=sid,active_sources=active,idle_sources=idle,
                          source_before=before,source_detached=detached,source_after=after,exit_codes=codes)
            logs=[(out/(label+'-%d.log'%i)).read_text() for i in range(2)]
            result=check(record,raw,logs,evidence); evidence['result']=result
            (out/(label+'-evidence.json')).write_text(json.dumps(evidence,indent=2)); results.append(evidence)
            if result['status']!='PASS' or codes!=[0,0]: raise ValueError(result)
        (out/'result.json').write_text(json.dumps(dict(status='PASS',source=source,states=results),indent=2))
    finally:
        for p in children:
            if p.poll() is None: p.terminate()
        for p in children:
            try: p.wait(timeout=5)
            except subprocess.TimeoutExpired: p.kill(); p.wait()
        for handle in handles: handle.close()
        if daemon.poll() is None: daemon.terminate()
        try: daemon.wait(timeout=15)
        except subprocess.TimeoutExpired: daemon.kill(); daemon.wait()
        audit.close(); log.close()


if __name__=='__main__': run()
