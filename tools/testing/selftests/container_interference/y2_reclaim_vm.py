#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Private anonymous-memory actors under common/separate ancestor limits."""
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


def run():
    os.umask(0o077); os.sched_setaffinity(0,{7})
    env=admission.environment(); admission.check_environment(env)
    out=Path('/tmp/y2-reclaim-evidence'); out.mkdir(mode=0o700)
    root=Path('/sys/fs/cgroup/cis-y2-reclaim'); root.mkdir()
    (root/'management').mkdir(); (root/'management/cgroup.procs').write_text(str(os.getpid()))
    (root/'cgroup.subtree_control').write_text('+cpu +memory +cpuset')
    parents=[]; roots=[]
    for i in range(2):
        p=root/('parent%d'%i); p.mkdir(); parents.append(p)
        (p/'cgroup.subtree_control').write_text('+cpu +memory +cpuset')
        (p/'memory.max').write_text(str(384<<20))
        for j in range(2):
            q=p/('root%d'%j); q.mkdir(); roots.append(q)
            (q/'memory.max').write_text(str(128<<20))
            (q/'cpuset.cpus').write_text('0-1'); (q/'cpuset.mems').write_text('0')
    args=SimpleNamespace(worker='/profile/session-worker',residue='/profile/session-residue',bpf='/profile/cis.bpf.o')
    source=source_manifest(args,env['boot_id']); permit=admission.create(source,env,time.monotonic_ns())
    (out/'permit.json').write_text(json.dumps(permit,indent=2))
    cases=[dict(name='common',actors=[0,1],parent_high=96<<20,private_high=None),
           dict(name='separate',actors=[0,2],parent_high=96<<20,private_high=None),
           dict(name='private',actors=[0,2],parent_high=None,private_high=16<<20)]
    order=[dict(case=c,round=r,enabled=v,label='%s%d%s'%(c['name'],r,'on' if v else 'off'))
           for r in range(3) for c in cases for v in ((False,True) if r%2==0 else (True,False))]
    plan=dict(schema='cis-y2-reclaim-plan-v1',cases=cases,order=order,window_ms=2000,
        workload_seconds=3,bytes_per_allocation=64<<20,source=source,
        roots=[dict(path=str(p),cgroup_id=p.stat().st_ino,parent_id=p.parent.stat().st_ino) for p in roots],
        parents=[dict(path=str(p),cgroup_id=p.stat().st_ino) for p in parents],
        cpus=[0,1],mems=[0],manager_cpu=7,
        limits='Configured ancestor pressure is not the reclaim target or a blocking-container identity.')
    (out/'plan.json').write_text(json.dumps(plan,indent=2))
    endpoint='/run/cis-y2-reclaim.sock'; log=(out/'controller.log').open('x')
    audit=(out/'requests.jsonl').open('x'); children=[]; handles=[]; states=[]
    daemon=subprocess.Popen(['/usr/bin/python3','/profile/session.py','--socket',endpoint,'--directory',str(out/'records'),
        '--worker',args.worker,'--residue',args.residue,'--bpf',args.bpf,'--admission-policy','prototype',
        '--prototype-permit',str(out/'permit.json'),'daemon'],stdout=log,stderr=log)

    def request(op,**kw):
        req=dict(version=1,op=op,**kw); begin=time.monotonic_ns()
        with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as sock:
            sock.settimeout(15); sock.connect(endpoint); sock.send(json.dumps(req).encode()); reply=json.loads(sock.recv(16384))
        retained=reply
        if op=='status' and reply.get('ok'):
            retained=dict(reply,data={k:reply['data'][k] for k in ('state','session_id','finalized') if k in reply['data']})
        audit.write(json.dumps(dict(before_ns=begin,after_ns=time.monotonic_ns(),request=req,response=retained))+'\n'); audit.flush()
        if not reply['ok']: raise RuntimeError(reply)
        return reply['data']

    def wait(sid,key):
        deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            row=request('status',session=sid)
            if row.get(key): return row
            if row.get('finalized'): raise RuntimeError(row)
            time.sleep(.02 if key=='window' else .1)
        raise TimeoutError(sid)

    def snapshot():
        return dict(begin_ns=time.monotonic_ns(),proc_stat=Path('/proc/stat').read_text(),
            memory=Path('/proc/meminfo').read_text(),controller_stat=Path('/proc/%d/stat'%daemon.pid).read_text(),
            groups=[dict(path=str(p),cgroup_id=p.stat().st_ino,**{n:(p/n).read_text() for n in
                ('cpu.stat','memory.events','memory.events.local','memory.current','memory.peak','memory.stat','memory.high')})
                for p in parents+roots],end_ns=time.monotonic_ns())

    try:
        deadline=time.monotonic()+10
        while not Path(endpoint).exists():
            if daemon.poll() is not None or time.monotonic()>deadline: raise RuntimeError('readiness')
            time.sleep(.02)
        targets=[request('register',path=str(p))['target'] for p in roots]
        for entry in order:
            c=entry['case']; label=entry['label']; sid=None
            for p in parents: (p/'memory.high').write_text(str(c['parent_high']) if c['parent_high'] else 'max')
            for i,p in enumerate(roots): (p/'memory.high').write_text(str(c['private_high']) if i==0 and c['private_high'] else 'max')
            before=snapshot()
            if entry['enabled']:
                sid=request('start',collector='reclaim',targets=[targets[i] for i in c['actors']],nonce=label,window_ms=2000)['session_id']
                window=wait(sid,'window')['window']; active=observe('reclaim')
            else:
                now=time.monotonic_ns(); window=dict(start_ns=now,end_ns=now+2_000_000_000); active=observe(None)
            start=max(window['start_ns']+300_000_000,time.monotonic_ns()+100_000_000)
            jobs=[]; running=[]
            for cpu,i in enumerate(c['actors']):
                name=label+'-%d.log'%i; h=(out/name).open('x'); handles.append(h)
                p=subprocess.Popen(['/session_launch',str(roots[i]),str(cpu),'/workload','reclaim','3',str(start)],stdout=h,stderr=h)
                children.append(p); running.append(p); jobs.append(dict(actor=i,cpu=cpu,log=name))
            if sid:
                row=wait(sid,'finalized')
                if not row.get('objects_absent'): raise ValueError('capture cleanup')
            else: time.sleep(max(0,(window['end_ns']-time.monotonic_ns())/1e9))
            captured=snapshot(); release_begin=time.monotonic_ns()
            for p in parents+roots: (p/'memory.high').write_text('max')
            release_end=time.monotonic_ns()
            codes=[p.wait(timeout=15) for p in running]
            if codes!=[0,0]: raise ValueError('workload exit')
            states.append(dict(**entry,session_id=sid,window=window,targets=targets,jobs=jobs,
                active_sources=active,idle_sources=observe(None),before=before,captured=captured,after=snapshot(),
                release_ns=[release_begin,release_end],exit_codes=codes))
            (out/(label+'-evidence.json')).write_text(json.dumps(states[-1],indent=2))
            (out/'partial.json').write_text(json.dumps(states,indent=2))
        (out/'result.json').write_text(json.dumps(dict(status='COLLECTED',states=states,source=source),indent=2))
    finally:
        for p in parents+roots: (p/'memory.high').write_text('max')
        for p in children:
            if p.poll() is None: p.terminate()
        for p in children:
            try: p.wait(timeout=5)
            except subprocess.TimeoutExpired: p.kill(); p.wait()
        for h in handles: h.close()
        if daemon.poll() is None: daemon.terminate()
        try: daemon.wait(timeout=15)
        except subprocess.TimeoutExpired: daemon.kill(); daemon.wait()
        audit.close(); log.close()


if __name__=='__main__': run()
