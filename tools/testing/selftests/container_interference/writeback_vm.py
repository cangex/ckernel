#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
import ctypes
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
from block_report import analyze
from writeback_check import case_order,check_case


def run():
    os.umask(0o077); os.sched_setaffinity(0,{7})
    if not Path('/cis-disposable-vm').exists(): raise PermissionError('disposable VM only')
    env=prototype_admission.environment(); prototype_admission.check_environment(env)
    out=Path('/tmp/writeback-evidence'); out.mkdir(mode=0o700)
    root=Path('/sys/fs/cgroup/cis-writeback'); root.mkdir(); (root/'management').mkdir()
    (root/'management/cgroup.procs').write_text(str(os.getpid()))
    (root/'cgroup.subtree_control').write_text('+cpu +memory +cpuset +io')
    roots=[]
    for i in range(2):
        p=root/('root%d'%i); p.mkdir(); (p/'memory.max').write_text(str(64<<20)); roots.append(p)
    args=SimpleNamespace(worker='/profile/session-worker',residue='/profile/session-residue',bpf='/profile/cis.bpf.o')
    source=source_manifest(args,env['boot_id']); permit=prototype_admission.create(source,env,time.monotonic_ns())
    (out/'permit.json').write_text(json.dumps(permit,indent=2))
    plan=dict(order=case_order(),rounds=3,buffered=True,bytes_per_actor=131072,window_ms=2000,
        cpu=[0,1],management_cpu=7,filesystem='ext4',sync_trigger='unregistered management syncfs',
        private='different files and devices',shared='two containers dirty disjoint pages of one inode',
        dirtying_actor_link='OBSERVED_TRANSITIONS_NOT_EXCLUSIVE_OWNER',inode_request_link='REQUIRED_CLOSED_CONTEXT')
    (out/'plan.json').write_text(json.dumps(plan,indent=2))
    fds=[os.open('/wb%d'%i,os.O_RDONLY|os.O_DIRECTORY) for i in range(2)]
    libc=ctypes.CDLL(None,use_errno=True); libc.syncfs.argtypes=[ctypes.c_int]; libc.syncfs.restype=ctypes.c_int
    def sync():
        for fd in fds:
            if libc.syncfs(fd): raise OSError(ctypes.get_errno(),'syncfs')
    sync()
    endpoint='/run/cis-writeback.sock'; log=(out/'controller.log').open('x')
    daemon=subprocess.Popen(['/usr/bin/python3','/profile/session.py','--socket',endpoint,'--directory',str(out/'records'),
        '--worker',args.worker,'--residue',args.residue,'--bpf',args.bpf,'--admission-policy','prototype',
        '--prototype-permit',str(out/'permit.json'),'daemon'],stdout=log,stderr=log)
    requests=(out/'requests.jsonl').open('x'); children=[]; handles=[]; results=[]

    def request(op,**kwargs):
        before=time.monotonic_ns(); req=dict(version=1,op=op,**kwargs)
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
        return dict(time_ns=time.monotonic_ns(),proc_stat=Path('/proc/stat').read_text(),memory=Path('/proc/meminfo').read_text(),
            roots=[{name:(p/name).read_text() for name in ('cpu.stat','memory.current','memory.peak','memory.events','io.stat')} for p in roots])

    try:
        deadline=time.monotonic()+10
        while not Path(endpoint).exists():
            if daemon.poll() is not None or time.monotonic()>deadline: raise RuntimeError('daemon readiness')
            time.sleep(.02)
        targets=[request('register',path=str(p))['target'] for p in roots]
        for label in plan['order']:
            case=label.split('-')[0]; collecting='-block' in label; sid=None
            selected=[fds[0],fds[1] if case=='private' else fds[0]]
            if collecting:
                sid=request('start',collector='block',targets=targets,nonce=label.replace('-',''),window_ms=2000)['session_id']
                window=wait(sid,'window')['window']; active=observe('block')
            else:
                now=time.monotonic_ns(); window=dict(start_ns=now,end_ns=now+2_000_000_000); active=observe(None)
            start=max(window['start_ns']+300_000_000,time.monotonic_ns()+100_000_000)
            before=snapshot(); running=[]
            for i,p in enumerate(roots):
                handle=(out/(label+'-%d.log'%i)).open('x'); handles.append(handle); fd=selected[i]
                child=subprocess.Popen(['/session_launch',str(p),str(i),'/writeback_workload',str(fd),str(i),str(start),label],
                    stdout=handle,stderr=handle,pass_fds=(fd,)); children.append(child); running.append(child)
            codes=[p.wait(timeout=10) for p in running]
            sync_begin=time.monotonic_ns(); sync(); sync_end=time.monotonic_ns(); after=snapshot()
            if codes!=[0,0] or sync_end>=window['end_ns']: raise ValueError(('workload completion/window',codes))
            logs=[(out/(label+'-%d.log'%i)).read_text() for i in range(2)]
            report=None; identities=None
            if sid:
                row=wait(sid,'finalized'); idle=observe(None)
                record=json.loads((out/'records'/(sid+'.json')).read_text())
                report=analyze(record,(out/'records'/(sid+'.jsonl')).read_bytes())
                identities=[record['root_identities'][t] for t in targets]
                (out/(label+'-report.json')).write_text(json.dumps(report,indent=2))
                if not row.get('objects_absent'): raise ValueError('capture cleanup')
            else: idle=observe(None)
            verified=[]
            for i,dirfd in enumerate(selected):
                fd=os.open(label,os.O_RDONLY,dir_fd=dirfd)
                try:
                    os.posix_fadvise(fd,i*131072,131072,os.POSIX_FADV_DONTNEED)
                    verified.append(os.pread(fd,131072,i*131072)==bytes([0x35+i])*131072)
                finally: os.close(fd)
            result=check_case(case,window,logs,[sync_begin,sync_end],verified,report,identities)
            evidence=dict(label=label,session_id=sid,window=window,active_sources=active,idle_sources=idle,
                targets=targets,before=before,after=after,exit_codes=codes,sync_interval_ns=[sync_begin,sync_end],verified=verified,result=result)
            (out/(label+'-evidence.json')).write_text(json.dumps(evidence,indent=2)); results.append(evidence)
            if result['status']!='PASS': raise ValueError(result)
        (out/'result.json').write_text(json.dumps(dict(status='PASS',source=source,states=results),indent=2))
    finally:
        for p in children:
            if p.poll() is None: p.terminate()
        for p in children:
            try: p.wait(timeout=5)
            except subprocess.TimeoutExpired: p.kill(); p.wait()
        for h in handles: h.close()
        for fd in fds: os.close(fd)
        if daemon.poll() is None: daemon.terminate()
        try: daemon.wait(timeout=15)
        except subprocess.TimeoutExpired: daemon.kill(); daemon.wait()
        requests.close(); log.close()


if __name__=='__main__': run()
