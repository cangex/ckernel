#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time
from types import SimpleNamespace

import prototype_admission as admission
from session import source_manifest
from source_switches import observe
from filesystem_report import analyze
from y3_filesystem_check import CASES,case_order,check_case
from filesystem_filter_control import check as check_filter


def filesystem_layout():
    rows=[]
    for i in range(2):
        nodes=[p for p in Path('/sys/class/block').glob('vd*')
               if (p/'serial').read_text().strip()=='cis-y3-fs%d'%i]
        if len(nodes)!=1: raise ValueError('unique scratch disk identity required')
        device=Path('/dev')/nodes[0].name
        with device.open('rb',buffering=0) as stream:
            stream.seek(1024); sb=stream.read(1024)
        compat=struct.unpack_from('<I',sb,92)[0]
        if struct.unpack_from('<H',sb,56)[0]!=0xef53 or bool(compat&0x1000)!=bool(i):
            raise ValueError('scratch filesystem feature mismatch')
        if os.stat('/fs%d'%i).st_dev!=device.stat().st_rdev: raise ValueError('scratch mount mismatch')
        rows.append(dict(serial='cis-y3-fs%d'%i,device=str(device),mount='/fs%d'%i,
                         uuid=sb[104:120].hex(),compat=compat,orphan_file=bool(compat&0x1000)))
    return rows


def run():
    os.umask(0o077); os.sched_setaffinity(0,{7})
    env=admission.environment(); admission.check_environment(env)
    out=Path('/tmp/y3-filesystem-evidence'); out.mkdir(mode=0o700)
    (out/'filesystem-layout.json').write_text(json.dumps(filesystem_layout(),indent=2))
    (out/'lease-checks.json').write_text(json.dumps(check_filter(),indent=2))
    root=Path('/sys/fs/cgroup/cis-y3-fs'); root.mkdir(); (root/'management').mkdir()
    (root/'management/cgroup.procs').write_text(str(os.getpid()))
    (root/'cgroup.subtree_control').write_text('+cpu +memory +cpuset +io')
    roots=[]; directories=[]
    for i in range(2):
        p=root/('root%d'%i); p.mkdir(); (p/'memory.max').write_text(str(128<<20)); roots.append(p)
        row=[]
        for disk in range(2):
            path=Path('/fs%d/private%d'%(disk,i)); path.mkdir()
            row.append(os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC))
        directories.append(row)
    args=SimpleNamespace(worker='/profile/session-worker',residue='/profile/session-residue',bpf='/profile/cis.bpf.o')
    source=source_manifest(args,env['boot_id']); permit=admission.create(source,env,time.monotonic_ns())
    (out/'permit.json').write_text(json.dumps(permit,indent=2))
    plan=dict(schema='cis-y3-filesystem-plan-v1',order=case_order(),cases=CASES,window_ms=2000,
        iterations=96,bytes_per_file=65536,source=source,cpus=[0,1],manager_cpu=7,
        features=['legacy_orphan_list','orphan_file'],private_directories=True,
        mounts=Path('/proc/self/mountinfo').read_text(),scope='public resources, not unique blockers')
    (out/'plan.json').write_text(json.dumps(plan,indent=2))
    endpoint='/run/cis-y3-filesystem.sock'; log=(out/'controller.log').open('x')
    requests=(out/'requests.jsonl').open('x'); children=[]; handles=[]; states=[]
    daemon=subprocess.Popen(['/usr/bin/python3','/profile/session.py','--socket',endpoint,'--directory',str(out/'records'),
        '--worker',args.worker,'--residue',args.residue,'--bpf',args.bpf,'--admission-policy','prototype',
        '--prototype-permit',str(out/'permit.json'),'daemon'],stdout=log,stderr=log)

    def request(op,**kw):
        req=dict(version=1,op=op,**kw); before=time.monotonic_ns()
        with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as sock:
            sock.settimeout(15); sock.connect(endpoint); sock.send(json.dumps(req).encode()); reply=json.loads(sock.recv(16384))
        retained=reply
        if op=='status' and reply.get('ok'):
            retained=dict(reply,data={k:reply['data'][k] for k in ('state','session_id','finalized') if k in reply['data']})
        requests.write(json.dumps(dict(before_ns=before,after_ns=time.monotonic_ns(),request=req,response=retained))+'\n'); requests.flush()
        if not reply['ok']: raise RuntimeError(reply)
        return reply['data']

    def wait(sid,field):
        deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            row=request('status',session=sid)
            if row.get(field): return row
            if row.get('finalized'): raise RuntimeError(row)
            time.sleep(.02 if field=='window' else .1)
        raise TimeoutError(sid)

    def snapshot():
        return dict(before_ns=time.monotonic_ns(),proc_stat=Path('/proc/stat').read_text(),
            memory=Path('/proc/meminfo').read_text(),native_audit=Path('/sys/kernel/debug/cis_fs_audit').read_text(),
            roots=[{n:(p/n).read_text() for n in ('cpu.stat','memory.current','memory.peak','memory.events','io.stat')} for p in roots],
            after_ns=time.monotonic_ns())

    try:
        deadline=time.monotonic()+10
        while not Path(endpoint).exists():
            if daemon.poll() is not None or time.monotonic()>deadline: raise RuntimeError('readiness')
            time.sleep(.02)
        targets=[request('register',path=str(p))['target'] for p in roots]
        for entry in plan['order']:
            label=entry['label']; case=entry['case']; c=CASES[case]; sid=None
            before=snapshot()
            if entry['enabled']:
                sid=request('start',collector='filesystem',filesystem='/fs%d'%c['selected'],
                    targets=targets,nonce=label,window_ms=2000)['session_id']
                window=wait(sid,'window')['window']; active=observe('filesystem')
            else:
                t=time.monotonic_ns(); window=dict(start_ns=t,end_ns=t+2_000_000_000); active=observe(None)
            start=max(window['start_ns']+300_000_000,time.monotonic_ns()+100_000_000)
            running=[]
            for i,p in enumerate(roots):
                fd=directories[i][c['disks'][i]]; h=(out/(label+'-%d.log'%i)).open('x'); handles.append(h)
                child=subprocess.Popen(['/session_launch',str(p),str(i),'/filesystem_workload',str(fd),str(i),str(start),label],
                    pass_fds=(fd,),stdout=h,stderr=h); children.append(child); running.append(child)
            codes=[p.wait(timeout=10) for p in running]; report=None; identities=None
            if sid:
                wait(sid,'finalized'); record=json.loads((out/'records'/(sid+'.json')).read_text())
                report=analyze(record,(out/'records'/(sid+'.jsonl')).read_bytes())
                identities=[record['root_identities'][t] for t in targets]
                (out/(label+'-report.json')).write_text(json.dumps(report,indent=2))
            else: time.sleep(max(0,(window['end_ns']-time.monotonic_ns())/1e9))
            idle=observe(None); after=snapshot()
            logs=[(out/(label+'-%d.log'%i)).read_text() for i in range(2)]
            checked=check_case(case,window,logs,report,identities)
            ev=dict(**entry,session_id=sid,targets=targets,window=window,before=before,after=after,
                active_sources=active,idle_sources=idle,exit_codes=codes,result=checked)
            states.append(ev); (out/(label+'-evidence.json')).write_text(json.dumps(ev,indent=2))
            (out/'partial.json').write_text(json.dumps(states,indent=2))
            if checked['status']!='PASS' or codes!=[0,0]: raise ValueError(checked)
        (out/'result.json').write_text(json.dumps(dict(status='PASS_SCOPED',source=source,states=states),indent=2))
    finally:
        for p in children:
            if p.poll() is None: p.terminate()
        for p in children:
            try: p.wait(timeout=5)
            except subprocess.TimeoutExpired: p.kill(); p.wait()
        for h in handles: h.close()
        for row in directories:
            for fd in row: os.close(fd)
        if daemon.poll() is None: daemon.terminate()
        try: daemon.wait(timeout=15)
        except subprocess.TimeoutExpired: daemon.kill(); daemon.wait()
        requests.close(); log.close()


if __name__=='__main__': run()
