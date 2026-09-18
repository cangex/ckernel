#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""X1 first-layer tests; not a holder, FD, or rwsem reader-set acceptance."""
import json
import os
from pathlib import Path
import socket
import subprocess
import time
from types import SimpleNamespace

import prototype_admission
from session import source_manifest
from sync_report import analyze
from sync_check import check


def run():
    os.umask(0o077)
    env=prototype_admission.environment();prototype_admission.check_environment(env)
    os.sched_setaffinity(0,{7})
    out=Path('/tmp/sync-evidence');out.mkdir(mode=0o700)
    root=Path('/sys/fs/cgroup/cis-sync');root.mkdir()
    (root/'management').mkdir();(root/'management/cgroup.procs').write_text(str(os.getpid()))
    (root/'cgroup.subtree_control').write_text('+cpu +memory +cpuset')
    args=SimpleNamespace(worker='/profile/session-worker',residue='/profile/session-residue',bpf='/profile/cis.bpf.o')
    source=source_manifest(args,env['boot_id'])
    permit=prototype_admission.create(source,env,time.monotonic_ns())
    (out/'permit.json').write_text(json.dumps(permit,indent=2))
    cases=['spinShared','spinPrivate','rwMixed','rwPrivate','readersOnly','tryWrite']
    plan=dict(cases=cases,repetitions=3,window_ms=2000,roots=2,operations_per_worker=16,
              scope='X1 E1 discovery only; owner closure and FD adapter not implemented',
              true_spin_hold_us=100,true_rwsem_hold_us=2000,performance_certification='NOT_ACCEPTED')
    (out/'plan.json').write_text(json.dumps(plan,indent=2))
    endpoint='/run/cis-sync.sock';log=(out/'controller.log').open('x')
    daemon=subprocess.Popen(['/usr/bin/python3','/profile/session.py','--socket',endpoint,'--directory',str(out/'records'),
                             '--worker',args.worker,'--residue',args.residue,'--bpf',args.bpf,
                             '--admission-policy','prototype','--prototype-permit',str(out/'permit.json'),'daemon'],stdout=log,stderr=log)
    requests=(out/'requests.jsonl').open('x');children=[];handles=[];results=[]

    def request(op,**fields):
        before=time.monotonic_ns();req=dict(version=1,op=op,**fields)
        with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as sock:
            sock.settimeout(15);sock.connect(endpoint);sock.send(json.dumps(req).encode());answer=json.loads(sock.recv(8192))
        requests.write(json.dumps(dict(before_ns=before,after_ns=time.monotonic_ns(),request=req,response=answer))+'\n');requests.flush()
        if not answer['ok']: raise RuntimeError(answer)
        return answer['data']

    def wait_record(sid,field):
        deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            row=request('status',session=sid)
            if row.get(field): return row
            if row.get('finalized'): raise RuntimeError(row)
            time.sleep(.01 if field=='window' else .1)
        raise TimeoutError(sid)

    def launch(label,index,family,slot,operation,start):
        handle=(out/(label+'-%d.log'%index)).open('x');handles.append(handle)
        child=subprocess.Popen(['/session_launch',str(root/('root%d'%(index%2))),str(index),'/sync_workload',
                                str(family),str(slot),str(operation),str(100 if family==1 else 2000),'16',str(start)],
                               stdout=handle,stderr=handle)
        children.append(child);return child

    try:
        deadline=time.monotonic()+10
        while not Path(endpoint).exists():
            if daemon.poll() is not None or time.monotonic()>deadline: raise RuntimeError('daemon readiness')
            time.sleep(.02)
        targets=[]
        for index in range(2):
            path=root/('root%d'%index);path.mkdir();targets.append(request('register',path=str(path))['target'])
        # OFF smoke uses the same fixture and container launcher before any collector is loaded.
        for family in (1,2):
            start=time.monotonic_ns()+300_000_000
            running=[launch('off%d'%family,i,family,0,i%2 if family==2 else 0,start) for i in range(4)]
            for child in running: assert child.wait(timeout=10)==0
        for repeat in range(3):
            for case in cases:
                label=case+str(repeat)
                sid=request('start',collector='sync',targets=targets,nonce=label,window_ms=2000)['session_id']
                window=wait_record(sid,'window')['window'];start=max(window['start_ns']+300_000_000,time.monotonic_ns()+100_000_000)
                family=1 if case.startswith('spin') else 2
                private=case.endswith('Private');count=2 if private else 4
                running=[]
                for i in range(count):
                    operation=1 if case=='readersOnly' or case=='rwMixed' and i%2==0 else 2 if case=='tryWrite' and i%2 else 0
                    running.append(launch(label,i,family,i if private else 0,operation,start))
                for child in running: assert child.wait(timeout=10)==0
                assert time.monotonic_ns()<window['end_ns'],'truth workload exceeded capture'
                row=wait_record(sid,'finalized')
                assert row['state']=='IDLE' and row.get('objects_absent'),row
                record=json.loads((out/'records'/(sid+'.json')).read_text())
                report=analyze(record,(out/'records'/(sid+'.jsonl')).read_bytes())
                truth=check(report,[(out/(label+'-%d.log'%i)).read_text() for i in range(count)],case in ('spinShared','rwMixed'))
                (out/(label+'-report.json')).write_text(json.dumps(report,indent=2))
                (out/(label+'-truth.json')).write_text(json.dumps(truth,indent=2))
                result=dict(label=label,session_id=sid,truth=truth['status'],matched=truth['matched_intervals'],quality=report['quality']['status'])
                results.append(result)
                (out/'partial.json').write_text(json.dumps(results,indent=2))
                assert truth['status']=='PASS',truth
                if private or case=='readersOnly': assert not truth['matched_intervals'],truth
        summary=dict(status='PASS',scope=plan['scope'],source=source,plan=plan,cases=results,
                     holder_coverage='NOT_IMPLEMENTED',performance_certification='NOT_ACCEPTED')
        (out/'result.json').write_text(json.dumps(summary,indent=2));print('CIS_SYNC_RESULT '+json.dumps(summary),flush=True)
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
        requests.close();log.close()


if __name__=='__main__': run()
