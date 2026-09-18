#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Three fixed high-rate FD sessions; no retries or raised source threshold."""
import json
import os
from pathlib import Path
import socket
import subprocess
import time
from types import SimpleNamespace

import prototype_admission as admission
from session import source_manifest
from source_switches import observe
from fd_guard_check import check


def run():
    os.umask(0o077);os.sched_setaffinity(0,{7})
    env=admission.environment();admission.check_environment(env)
    out=Path('/tmp/fd-guard-evidence');out.mkdir(mode=0o700)
    root=Path('/sys/fs/cgroup/cis-fd-guard');root.mkdir()
    (root/'management').mkdir();(root/'management/cgroup.procs').write_text(str(os.getpid()))
    (root/'cgroup.subtree_control').write_text('+cpu +memory +cpuset')
    args=SimpleNamespace(worker='/profile/session-worker',residue='/profile/session-residue',bpf='/profile/cis.bpf.o')
    source=source_manifest(args,env['boot_id']);permit=admission.create(source,env,time.monotonic_ns())
    plan=dict(schema='cis-fd-guard-v1',repetitions=3,off_rounds=1,seconds=4,window_ms=2000,
              collector='fd',entry_rate_limit=200000,source=source)
    for name,data in (('permit',permit),('plan',plan)):
        (out/(name+'.json')).write_text(json.dumps(data,indent=2))
    endpoint='/run/cis-fd-guard.sock';log=(out/'controller.log').open('x');audit=(out/'requests.jsonl').open('x')
    daemon=subprocess.Popen(['/usr/bin/python3','/profile/session.py','--socket',endpoint,'--directory',str(out/'records'),
        '--worker',args.worker,'--residue',args.residue,'--bpf',args.bpf,'--admission-policy','prototype',
        '--prototype-permit',str(out/'permit.json'),'daemon'],stdout=log,stderr=log)
    children=[];handles=[];results=[]

    def request(op,**fields):
        before=time.monotonic_ns();req=dict(version=1,op=op,**fields)
        with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as sock:
            sock.settimeout(15);sock.connect(endpoint);sock.send(json.dumps(req).encode());reply=json.loads(sock.recv(8192))
        audit.write(json.dumps(dict(before_ns=before,after_ns=time.monotonic_ns(),request=req,response=reply))+'\n');audit.flush()
        if not reply['ok']: raise RuntimeError(reply)
        return reply['data']

    def wait_record(sid,field):
        deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            row=request('status',session=sid)
            if row.get(field): return row
            if row.get('finalized'): raise RuntimeError(row)
            time.sleep(.02)
        raise TimeoutError(sid)

    def launch(label,start):
        running=[]
        for index in range(2):
            handle=(out/(label+'-%d.log'%index)).open('x');handles.append(handle)
            child=subprocess.Popen(['/session_launch',str(root/('root%d'%index)),str(index*2),'/workload',
                'fd-storm','4',str(start)],stdout=handle,stderr=handle)
            children.append(child);running.append(child)
        return running

    try:
        deadline=time.monotonic()+10
        while not Path(endpoint).exists():
            if daemon.poll() is not None or time.monotonic()>deadline: raise RuntimeError('controller readiness')
            time.sleep(.02)
        targets=[]
        for index in range(2):
            path=root/('root%d'%index);path.mkdir();targets.append(request('register',path=str(path))['target'])
        off_before=observe()
        for child in launch('off',time.monotonic_ns()+500_000_000): assert child.wait(timeout=10)==0
        (out/'off-sources.json').write_text(json.dumps(dict(before=off_before,after=observe()),indent=2))
        for repeat in range(3):
            label='storm%d'%repeat
            sid=request('start',collector='fd',targets=targets,nonce=label,window_ms=2000)['session_id']
            window=wait_record(sid,'window')['window'];active=observe('fd')
            running=launch(label,max(window['start_ns'],time.monotonic_ns()+100_000_000))
            wait_record(sid,'finalized');idle=observe()
            for child in running: assert child.wait(timeout=10)==0
            record=json.loads((out/'records'/(sid+'.json')).read_text())
            raw=(out/'records'/(sid+'.jsonl')).read_bytes()
            sources=dict(active=active,idle=idle)
            result=check(record,raw,[(out/(label+'-%d.log'%i)).read_text() for i in range(2)],sources)
            results.append(dict(label=label,session_id=sid,result=result,sources=sources))
            (out/'partial.json').write_text(json.dumps(results,indent=2))
            assert result['status']=='PASS',result
        result=dict(status='PASS',plan=plan,cases=results,source=source)
        (out/'result.json').write_text(json.dumps(result,indent=2));print('CIS_FD_GUARD '+json.dumps(result),flush=True)
    finally:
        for child in children:
            if child.poll() is None: child.terminate()
        for child in children:
            try: child.wait(timeout=5)
            except subprocess.TimeoutExpired: child.kill();child.wait()
        for handle in handles: handle.close()
        if daemon.poll() is None: daemon.terminate()
        try: daemon.wait(timeout=15)
        except subprocess.TimeoutExpired: daemon.kill();daemon.wait()
        audit.close();log.close()


if __name__=='__main__': run()
