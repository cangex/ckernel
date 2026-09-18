#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Four active containers, mixed ordinary operations, bounded open-loop cost bridge."""
import json
import os
from pathlib import Path
import socket
import subprocess
import time
from types import SimpleNamespace

import prototype_admission as admission
from collector_manifest import COLLECTORS
from owner_report import fields
from session import source_manifest
from source_switches import observe
from unified_report import analyze


def order():
    modes=['off']+list(COLLECTORS)
    return [(r,m) for r in range(3) for m in (modes if r%2==0 else list(reversed(modes)))]


def run():
    os.umask(0o077); os.sched_setaffinity(0,{7})
    env=admission.environment(); admission.check_environment(env)
    out=Path('/tmp/joint-evidence'); out.mkdir(mode=0o700)
    root=Path('/sys/fs/cgroup/cis-joint'); root.mkdir(); (root/'management').mkdir()
    (root/'management/cgroup.procs').write_text(str(os.getpid()))
    (root/'cgroup.subtree_control').write_text('+cpu +memory +cpuset')
    roots=[]
    for i in range(4):
        p=root/('root%d'%i); p.mkdir(); (p/'memory.max').write_text(str(64<<20)); roots.append(p)
    args=SimpleNamespace(worker='/profile/session-worker',residue='/profile/session-residue',bpf='/profile/cis.bpf.o')
    source=source_manifest(args,env['boot_id']); permit=admission.create(source,env,time.monotonic_ns())
    (out/'permit.json').write_text(json.dumps(permit,indent=2))
    plan=dict(schema='cis-x7-joint-plan-v1',source=source,order=order(),modes=['off']+list(COLLECTORS),rounds=3,
        cpus=[0,0,1,1],workloads=['file','file','vma','vma'],management_cpu=7,
        offered_per_actor=1500,period_ns=2_000_000,timeout_ns=100_000_000,
        scope='native file and VMA operations, four active containers; no injected kernel delays',
        off='controller idle without attached probes, not absent-CIS baseline',
        captures=30,p99='record_only',throughput='completed at fixed offered rate, not saturation throughput',
        clock_ticks=os.sysconf('SC_CLK_TCK'),
        targets_by_round=[[0,2],[1,3],[0,3]],source_generation='same kernel and collector bundle per cohort')
    (out/'plan.json').write_text(json.dumps(plan,indent=2))
    endpoint='/run/cis-joint.sock'; log=(out/'controller.log').open('x'); audit=(out/'requests.jsonl').open('x')
    daemon=subprocess.Popen(['/usr/bin/python3','/profile/session.py','--socket',endpoint,'--directory',str(out/'records'),
        '--worker',args.worker,'--residue',args.residue,'--bpf',args.bpf,'--admission-policy','prototype',
        '--prototype-permit',str(out/'permit.json'),'daemon'],stdout=log,stderr=log)
    children=[]; handles=[]; results=[]

    def request(op,**args):
        before=time.monotonic_ns(); req=dict(version=1,op=op,**args)
        with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as sock:
            sock.settimeout(15); sock.connect(endpoint); sock.send(json.dumps(req).encode()); reply=json.loads(sock.recv(16384))
        retained=reply
        if op=='status' and reply.get('ok'):
            retained=dict(reply,data={k:reply['data'][k] for k in ('state','session_id','finalized','prototype_sessions_started') if k in reply['data']})
        audit.write(json.dumps(dict(before_ns=before,after_ns=time.monotonic_ns(),request=req,response=retained))+'\n'); audit.flush()
        if not reply['ok']: raise RuntimeError(reply)
        return reply['data']

    def wait(sid,key):
        limit=time.monotonic()+20
        while time.monotonic()<limit:
            row=request('status',session=sid)
            if row.get(key): return row
            if row.get('finalized'): raise ValueError(row)
            time.sleep(.1)
        raise TimeoutError(key)

    def snapshot():
        return dict(time_ns=time.monotonic_ns(),proc_stat=Path('/proc/stat').read_text(),
            memory=Path('/proc/meminfo').read_text(),softirqs=Path('/proc/softirqs').read_text(),
            roots=[{name:(p/name).read_text() for name in ('cpu.stat','memory.current','memory.peak','memory.events')} for p in roots])

    try:
        limit=time.monotonic()+10
        while not Path(endpoint).exists():
            if daemon.poll() is not None or time.monotonic()>limit: raise RuntimeError('daemon readiness')
            time.sleep(.02)
        targets=[request('register',path=str(p))['target'] for p in roots]
        for round_number,mode in plan['order']:
            label=mode+str(round_number); start=time.monotonic_ns()+500_000_000; running=[]; before=snapshot()
            for i in range(4):
                h=(out/('%s-%d.log'%(label,i))).open('x'); handles.append(h)
                p=subprocess.Popen(['/session_launch',str(roots[i]),str(plan['cpus'][i]),'/joint_workload',plan['workloads'][i],str(start)],stdout=h,stderr=h)
                children.append(p); running.append(p)
            time.sleep(max(0,(start-time.monotonic_ns())/1e9)+.15)
            if any(p.poll() is not None for p in running): raise ValueError('workload exited before capture')
            sid=None; report=None; record=None; selected=[targets[i] for i in plan['targets_by_round'][round_number]]
            if mode!='off':
                sid=request('start',collector=mode,targets=selected,nonce=label)['session_id']
                active=wait(sid,'window'); switches=observe(mode); done=wait(sid,'finalized')
                record=json.loads((out/'records'/(sid+'.json')).read_text())
                if not done.get('objects_absent') or done['state']=='FAULTED': raise ValueError('unverified capture cleanup')
                report=analyze(record,(out/'records'/(sid+'.jsonl')).read_bytes())
                (out/(label+'-explanation.json')).write_text(json.dumps(report,indent=2))
            else: switches=observe(None)
            codes=[p.wait(timeout=10) for p in running]; after=snapshot(); work=[]
            for i in range(4):
                rows=[fields(v) for v in (out/('%s-%d.log'%(label,i))).read_text().splitlines() if v.startswith('CIS_JOINT_WORK ')]
                if len(rows)!=1 or rows[0]['errors'] or rows[0]['completed']!=1500: raise ValueError('business correctness')
                work.append(rows[0])
            if codes!=[0]*4: raise ValueError(('business exit',codes))
            if record and not (start<record['window']['start_ns']<record['window']['end_ns']<min(v['end_ns'] for v in work)):
                raise ValueError('business does not cover capture')
            result=dict(label=label,round=round_number,mode=mode,session_id=sid,targets=selected,all_targets=targets,
                start_ns=start,workload=work,before=before,after=after,exit_codes=codes,
                active_sources=switches,idle_sources=observe(None),
                quality=report['quality'] if report else dict(status='NOT_COLLECTED'))
            (out/(label+'-evidence.json')).write_text(json.dumps(result,indent=2)); results.append(result)
        (out/'result.json').write_text(json.dumps(dict(schema='cis-x7-joint-result-v1',source=source,
            status='PASS' if all(r['quality']['status'] in ('PASS','NOT_COLLECTED') for r in results) else 'FAIL',
            states=results,performance_certification='NOT_ACCEPTED'),indent=2))
    finally:
        for p in children:
            if p.poll() is None: p.terminate()
        for p in children:
            try: p.wait(timeout=5)
            except subprocess.TimeoutExpired: p.kill(); p.wait()
        if daemon.poll() is None: daemon.terminate()
        try: daemon.wait(timeout=15)
        except subprocess.TimeoutExpired: daemon.kill(); daemon.wait()
        for h in handles: h.close()
        audit.close(); log.close()


if __name__=='__main__': run()
