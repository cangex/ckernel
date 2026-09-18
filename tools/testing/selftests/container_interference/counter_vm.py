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
from counter_check import check

CASES = ['sameLeaf', 'sameAncestor', 'private', 'limitFailure', 'frequency', 'migration']


def run():
    os.umask(0o077); os.sched_setaffinity(0, {7})
    env=prototype_admission.environment(); prototype_admission.check_environment(env)
    if Path('/sys/module/cis_observe/parameters/counter_shift').read_text().strip()!='0':
        raise ValueError('fixture needs frozen full-call sampling, not a production coverage claim')
    out=Path('/tmp/counter-evidence'); out.mkdir(mode=0o700)
    root=Path('/sys/fs/cgroup/cis-counter'); root.mkdir()
    (root/'management').mkdir(); (root/'management/cgroup.procs').write_text(str(os.getpid()))
    (root/'cgroup.subtree_control').write_text('+cpu +memory +cpuset')
    args=SimpleNamespace(worker='/profile/session-worker',residue='/profile/session-residue',bpf='/profile/cis.bpf.o')
    source=source_manifest(args, env['boot_id'])
    permit=prototype_admission.create(source,env,time.monotonic_ns())
    (out/'permit.json').write_text(json.dumps(permit,indent=2))
    plan=dict(cases=CASES,repetitions=3,window_ms=2000,roots=2,sample_shift=0,
              operations_per_worker=16,frequency_first_worker=8,
              scope='X2 actual updates and rollback; stable fixture only, not native object lifetime or contention cause')
    (out/'plan.json').write_text(json.dumps(plan,indent=2))
    endpoint='/run/cis-counter.sock'; log=(out/'controller.log').open('x')
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

    def launch(label,case,index,start,count=None):
        slot=index+2 if case=='private' else 1 if case in ('sameAncestor','limitFailure') else 0
        leaf=index if case in ('sameAncestor','limitFailure') else 0
        pages=64 if case=='limitFailure' else 1
        operation=0 if case=='sameLeaf' else 1
        n=count if count is not None else 8 if case=='frequency' and index==0 else 16
        handle=(out/(label+'-%d.log'%index)).open('x'); handles.append(handle)
        child=subprocess.Popen(['/session_launch',str(root/('root%d'%index)),str(index),'/counter_workload',
            str(slot),str(leaf),str(operation),str(pages),str(n),str(start),str(int(case=='migration'))],stdout=handle,stderr=handle)
        children.append(child); return child

    try:
        deadline=time.monotonic()+10
        while not Path(endpoint).exists():
            if daemon.poll() is not None or time.monotonic()>deadline: raise RuntimeError('daemon readiness')
            time.sleep(.02)
        targets=[]
        for i in range(2):
            p=root/('root%d'%i); p.mkdir(); targets.append(request('register',path=str(p))['target'])
        observe(None)
        start=time.monotonic_ns()+300_000_000
        off=[launch('off','sameLeaf',i,start) for i in range(2)]
        for p in off: assert p.wait(timeout=10)==0
        for repeat in range(3):
            for case in CASES:
                label=case+str(repeat)
                sid=request('start',collector='counter',targets=targets,nonce=label,window_ms=2000)['session_id']
                window=wait(sid,'window')['window']; active=observe('counter')
                start=max(window['start_ns']+300_000_000,time.monotonic_ns()+100_000_000)
                running=[launch(label,case,i,start) for i in range(2)]
                for p in running: assert p.wait(timeout=10)==0
                assert time.monotonic_ns()<window['end_ns'],'fixture outside window'
                row=wait(sid,'finalized'); idle=observe(None)
                (out/(label+'-boundaries.json')).write_text(json.dumps(dict(active_sources=active,idle_sources=idle),indent=2))
                record=json.loads((out/'records'/(sid+'.json')).read_text())
                report=analyze(record,(out/'records'/(sid+'.jsonl')).read_bytes())
                truth=check(report,[(out/(label+'-%d.log'%i)).read_text() for i in range(2)],case!='private',case=='limitFailure')
                (out/(label+'-report.json')).write_text(json.dumps(report,indent=2))
                (out/(label+'-truth.json')).write_text(json.dumps(truth,indent=2))
                results.append(dict(label=label,session_id=sid,truth=truth))
                (out/'partial.json').write_text(json.dumps(results,indent=2))
                assert row.get('objects_absent') and truth['status']=='PASS',(row,truth)
        result=dict(status='PASS',plan=plan,source=source,cases=results,performance_certification='NOT_ACCEPTED')
        (out/'result.json').write_text(json.dumps(result,indent=2))
        print('CIS_COUNTER_RESULT '+json.dumps(result),flush=True)
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
        requests.close(); log.close()


if __name__=='__main__': run()
