#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Private container mappings: shared ancestor and selected page-zone checks."""
import errno
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


def lease_checks(out):
    path='/sys/kernel/debug/cis_backend_filter'
    events=[]
    fd=os.open(path,os.O_RDWR|os.O_CLOEXEC)
    try:
        try:
            other=os.open(path,os.O_RDWR|os.O_CLOEXEC)
        except OSError as e:
            if e.errno!=errno.EBUSY: raise
            events.append('exclusive_open')
        else:
            os.close(other); raise AssertionError('second lease accepted')
        for bad in (b'../bad *\n',b'page_zone 0,0\n',b'page_zone 1024\n'):
            try: os.write(fd,bad)
            except OSError as e:
                if e.errno not in (errno.EINVAL,errno.E2BIG): raise
            else: raise AssertionError('invalid selection accepted')
        good=b'page_zone 0\n'; os.write(fd,good)
        try: os.write(fd,b'page_zone 1\n')
        except OSError as e:
            if e.errno!=errno.EBUSY: raise
        else: raise AssertionError('mutable lease')
        if os.read(fd,160)!=good: raise AssertionError('selection readback')
        events.extend(['invalid_rejected','exact_readback','immutable_selection'])
    finally: os.close(fd)
    observe(None)
    # Only the child owns this new lease; normal process teardown must clear it.
    child=os.fork()
    if not child:
        try:
            f=os.open(path,os.O_RDWR|os.O_CLOEXEC); os.write(f,b'page_zone 0\n')
        except BaseException: os._exit(2)
        os._exit(0)
    if os.waitpid(child,0)[1]: raise AssertionError('lease crash setup')
    observe(None); events.append('process_exit_clears_selection')
    child=os.fork()
    if not child:
        os.setgroups([]); os.setgid(65534); os.setuid(65534)
        try: f=os.open(path,os.O_RDWR|os.O_CLOEXEC)
        except OSError as e: os._exit(0 if e.errno in (errno.EACCES,errno.EPERM) else 3)
        os.close(f); os._exit(4)
    if os.waitpid(child,0)[1]: raise AssertionError('unprivileged lease')
    events.append('unprivileged_rejected')
    (out/'lease-checks.json').write_text(json.dumps(dict(status='PASS',checks=events),indent=2))


def run():
    os.umask(0o077); os.sched_setaffinity(0,{7})
    env=admission.environment(); admission.check_environment(env)
    out=Path('/tmp/y2-memory-evidence'); out.mkdir(mode=0o700)
    if Path('/sys/devices/system/node/online').read_text().strip()!='0-1':
        raise ValueError('two guest NUMA nodes required')
    for name in ('counter_shift','page_shift'):
        if Path('/sys/module/cis_observe/parameters',name).read_text().strip()!='6':
            raise ValueError('default 1/64 source sampling required')
    lease_checks(out)
    root=Path('/sys/fs/cgroup/cis-y2-memory'); root.mkdir(); (root/'management').mkdir()
    (root/'management/cgroup.procs').write_text(str(os.getpid()))
    (root/'cgroup.subtree_control').write_text('+cpu +memory +cpuset')
    parents=[]; roots=[]
    for i in range(2):
        parent=root/('parent%d'%i); parent.mkdir()
        (parent/'cgroup.subtree_control').write_text('+cpu +memory +cpuset')
        (parent/'memory.max').write_text(str(192<<20)); parents.append(parent)
        for j in range(2):
            p=parent/('root%d'%j); p.mkdir(); (p/'memory.max').write_text(str(64<<20))
            (p/'cpuset.cpus').write_text('0-1'); (p/'cpuset.mems').write_text('0'); roots.append(p)
    args=SimpleNamespace(worker='/profile/session-worker',residue='/profile/session-residue',bpf='/profile/cis.bpf.o')
    source=source_manifest(args,env['boot_id']); permit=admission.create(source,env,time.monotonic_ns())
    (out/'permit.json').write_text(json.dumps(permit,indent=2))
    cases=[dict(name='common',collector='counter',actors=[0,1]),
           dict(name='separate',collector='counter',actors=[0,2]),
           dict(name='zone0',collector='page_backend',actors=[0,1],backend=dict(cache='page_zone',nodes=[0])),
           dict(name='zone1',collector='page_backend',actors=[0,1],backend=dict(cache='page_zone',nodes=[1]))]
    order=[dict(case=c,round=r,enabled=on,label='%s%d%s'%(c['name'],r,'on' if on else 'off'))
           for r in range(3) for c in cases for on in ((False,True) if r%2==0 else (True,False))]
    plan=dict(schema='cis-y2-memory-plan-v1',cases=cases,order=order,source=source,
              roots=[dict(path=str(p),cgroup_id=p.stat().st_ino,parent_id=p.parent.stat().st_ino) for p in roots],
              common_cgroup_id=root.stat().st_ino,operations=16,bytes_per_operation=8<<20,
              sample_shift=6,window_ms=2000,cpus=[0,1],mems=[0],manager_cpu=7,
              host_scope='isolated VM',claim='native participation and ownership, not causal blocking')
    (out/'plan.json').write_text(json.dumps(plan,indent=2))
    endpoint='/run/cis-y2-memory.sock'; log=(out/'controller.log').open('x')
    requests=(out/'requests.jsonl').open('x')
    daemon=subprocess.Popen(['/usr/bin/python3','/profile/session.py','--socket',endpoint,'--directory',str(out/'records'),
        '--worker',args.worker,'--residue',args.residue,'--bpf',args.bpf,'--admission-policy','prototype',
        '--prototype-permit',str(out/'permit.json'),'daemon'],stdout=log,stderr=log)
    children=[]; handles=[]; states=[]

    def request(op,**kw):
        before=time.monotonic_ns(); req=dict(version=1,op=op,**kw)
        with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as sock:
            sock.settimeout(15); sock.connect(endpoint); sock.send(json.dumps(req).encode()); reply=json.loads(sock.recv(16384))
        retained=reply
        if op=='status' and reply.get('ok'):
            retained=dict(reply,data={k:reply['data'][k] for k in ('state','session_id','finalized') if k in reply['data']})
        requests.write(json.dumps(dict(before_ns=before,after_ns=time.monotonic_ns(),request=req,response=retained))+'\n'); requests.flush()
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
        return dict(time_ns=time.monotonic_ns(),proc_stat=Path('/proc/stat').read_text(),
            memory=Path('/proc/meminfo').read_text(),controller_stat=Path('/proc/%d/stat'%daemon.pid).read_text(),
            page_audit=Path('/sys/kernel/debug/cis_page_audit').read_text(),
            counter_audit=Path('/sys/kernel/debug/cis_counter_audit').read_text(),
            roots=[{n:(p/n).read_text() for n in ('cpu.stat','memory.current','memory.peak','memory.events','cpuset.mems.effective')} for p in roots])

    try:
        deadline=time.monotonic()+10
        while not Path(endpoint).exists():
            if daemon.poll() is not None or time.monotonic()>deadline: raise RuntimeError('readiness')
            time.sleep(.02)
        registered=[request('register',path=str(p))['target'] for p in roots]
        for entry in order:
            c=entry['case']; label=entry['label']; sid=None
            if entry['enabled']:
                selection=dict(backend=c['backend']) if 'backend' in c else {}
                sid=request('start',collector=c['collector'],targets=[registered[i] for i in c['actors']],
                            nonce=label,window_ms=2000,**selection)['session_id']
                window=wait(sid,'window')['window']; active=observe(c['collector'])
            else:
                now=time.monotonic_ns(); window=dict(start_ns=now,end_ns=now+2_000_000_000); active=observe(None)
            start=max(window['start_ns']+300_000_000,time.monotonic_ns()+100_000_000)
            before=snapshot(); jobs=[]; running=[]
            for cpu,actor in enumerate(c['actors']):
                name=label+'-%d.log'%actor; h=(out/name).open('x'); handles.append(h)
                p=subprocess.Popen(['/session_launch',str(roots[actor]),str(cpu),'/counter_mem_workload',str(start)],stdout=h,stderr=h)
                children.append(p); running.append(p); jobs.append(dict(actor=actor,log=name,cpu=cpu))
            codes=[p.wait(timeout=10) for p in running]; after=snapshot()
            if codes!=[0,0] or after['time_ns']>=window['end_ns']: raise ValueError('workload completion/window')
            if sid:
                row=wait(sid,'finalized')
                if not row.get('objects_absent'): raise ValueError('capture cleanup')
            idle=observe(None)
            state=dict(**entry,session_id=sid,window=window,active_sources=active,idle_sources=idle,
                       targets=registered,jobs=jobs,before=before,after=after,exit_codes=codes)
            states.append(state); (out/(label+'-evidence.json')).write_text(json.dumps(state,indent=2))
            (out/'partial.json').write_text(json.dumps(states,indent=2))
        (out/'result.json').write_text(json.dumps(dict(status='COLLECTED',states=states,source=source),indent=2))
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
