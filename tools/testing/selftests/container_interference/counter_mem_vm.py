#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
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
from counter_report import analyze
from counter_bridge_check import check


def run():
    os.umask(0o077); os.sched_setaffinity(0, {7})
    env=prototype_admission.environment(); prototype_admission.check_environment(env)
    if Path('/sys/module/cis_observe/parameters/counter_shift').read_text().strip()!='6':
        raise ValueError('ordinary bridge must use default 1/64 source sampling')
    out=Path('/tmp/counter-mem-evidence'); out.mkdir(mode=0o700)
    root=Path('/sys/fs/cgroup/cis-counter-mem'); root.mkdir()
    (root/'management').mkdir(); (root/'management/cgroup.procs').write_text(str(os.getpid()))
    (root/'cgroup.subtree_control').write_text('+cpu +memory +cpuset')
    roots=[]
    for i in range(2):
        p=root/('root%d'%i); p.mkdir(); (p/'memory.max').write_text(str(64 << 20)); roots.append(p)
    args=SimpleNamespace(worker='/profile/session-worker',residue='/profile/session-residue',bpf='/profile/cis.bpf.o')
    source=source_manifest(args,env['boot_id'])
    permit=prototype_admission.create(source,env,time.monotonic_ns())
    (out/'permit.json').write_text(json.dumps(permit,indent=2))
    order=['off0','counter0','counter1','off1','off2','counter2']
    plan=dict(order=order,operations=16,bytes_per_operation=8 << 20,roots=2,sample_shift=6,
              memory_max_bytes=64 << 20,window_ms=2000,cpu=[0,1],management_cpu=7,
              scope='fixed ordinary mmap/touch/munmap bridge; descriptive n=3 cost screen, not performance acceptance')
    (out/'plan.json').write_text(json.dumps(plan,indent=2))
    endpoint='/run/cis-counter-mem.sock'; log=(out/'controller.log').open('x')
    daemon=subprocess.Popen(['/usr/bin/python3','/profile/session.py','--socket',endpoint,'--directory',str(out/'records'),
        '--worker',args.worker,'--residue',args.residue,'--bpf',args.bpf,
        '--admission-policy','prototype','--prototype-permit',str(out/'permit.json'),'daemon'],stdout=log,stderr=log)
    requests=(out/'requests.jsonl').open('x'); children=[]; handles=[]; results=[]

    def request(op,**fields):
        before=time.monotonic_ns(); req=dict(version=1,op=op,**fields)
        with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as sock:
            sock.settimeout(15); sock.connect(endpoint); sock.send(json.dumps(req).encode()); answer=json.loads(sock.recv(8192))
        requests.write(json.dumps(dict(before_ns=before,after_ns=time.monotonic_ns(),request=req,response=answer))+'\n'); requests.flush()
        if not answer['ok']: raise RuntimeError(answer)
        return answer['data']

    def wait(sid,field):
        deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            row=request('status',session=sid)
            if row.get(field): return row
            if row.get('finalized'): raise RuntimeError(row)
            time.sleep(.02 if field=='window' else .1)
        raise TimeoutError(sid)

    def snapshot():
        return dict(time_ns=time.monotonic_ns(),proc_stat=Path('/proc/stat').read_text(),
                    memory=Path('/proc/meminfo').read_text(),
                    roots=[{name:(p/name).read_text() for name in ('cpu.stat','memory.current','memory.peak','memory.events')} for p in roots])

    try:
        deadline=time.monotonic()+10
        while not Path(endpoint).exists():
            if daemon.poll() is not None or time.monotonic()>deadline: raise RuntimeError('daemon readiness')
            time.sleep(.02)
        targets=[request('register',path=str(p))['target'] for p in roots]
        for label in order:
            sid=None
            if label.startswith('counter'):
                sid=request('start',collector='counter',targets=targets,nonce=label,window_ms=2000)['session_id']
                window=wait(sid,'window')['window']; active=observe('counter')
            else:
                now=time.monotonic_ns(); window=dict(start_ns=now,end_ns=now+2_000_000_000); active=observe(None)
            start=max(window['start_ns']+300_000_000,time.monotonic_ns()+100_000_000)
            before=snapshot(); running=[]
            for i,p in enumerate(roots):
                handle=(out/(label+'-%d.log'%i)).open('x'); handles.append(handle)
                child=subprocess.Popen(['/session_launch',str(p),str(i),'/counter_mem_workload',str(start)],stdout=handle,stderr=handle)
                children.append(child); running.append(child)
            codes=[p.wait(timeout=10) for p in running]
            after=snapshot()
            if codes!=[0,0] or after['time_ns']>=window['end_ns']: raise ValueError('workload completion or window')
            if sid:
                row=wait(sid,'finalized'); idle=observe(None)
                record=json.loads((out/'records'/(sid+'.json')).read_text())
                report=analyze(record,(out/'records'/(sid+'.jsonl')).read_bytes())
                result=check(record,report,[(out/(label+'-%d.log'%i)).read_text() for i in range(2)],
                             [record['root_identities'][key] for key in targets])
                (out/(label+'-report.json')).write_text(json.dumps(report,indent=2))
                if not row.get('objects_absent'): raise ValueError('capture cleanup')
            else:
                idle=observe(None); result=dict(status='PASS',scope='workload exit only; independent verifier checks operation records')
            evidence=dict(label=label,session_id=sid,window=window,active_sources=active,idle_sources=idle,
                          targets=targets,before=before,after=after,exit_codes=codes,result=result)
            (out/(label+'-evidence.json')).write_text(json.dumps(evidence,indent=2)); results.append(evidence)
            if result['status']!='PASS': raise ValueError(result)
        (out/'result.json').write_text(json.dumps(dict(status='PASS',source=source,plan=plan,states=results),indent=2))
    finally:
        for p in children:
            if p.poll() is None: p.terminate()
        for p in children:
            try: p.wait(timeout=5)
            except subprocess.TimeoutExpired: p.kill(); p.wait()
        for h in handles: h.close()
        if daemon.poll() is None: daemon.terminate()
        try: daemon.wait(timeout=15)
        except subprocess.TimeoutExpired: daemon.kill(); daemon.wait()
        requests.close(); log.close()


if __name__=='__main__': run()
