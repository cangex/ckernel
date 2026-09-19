#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
import json
import os
from pathlib import Path
import select
import re
import socket
import subprocess
import time
from types import SimpleNamespace

import prototype_admission
from session import source_manifest
from source_switches import observe
from block_report import analyze
from tag_fixture_check import order, check


def run():
    os.umask(0o077); os.sched_setaffinity(0,{7})
    if not Path('/cis-disposable-vm').exists(): raise PermissionError('dedicated VM only')
    env=prototype_admission.environment(); prototype_admission.check_environment(env)
    out=Path('/tmp/tag-evidence'); out.mkdir(mode=0o700)
    root=Path('/sys/fs/cgroup/cis-tags'); root.mkdir(); (root/'management').mkdir()
    (root/'management/cgroup.procs').write_text(str(os.getpid()))
    (root/'cgroup.subtree_control').write_text('+cpu +memory +cpuset +io')
    roots=[]
    for i in range(2):
        p=root/('root%d'%i); p.mkdir(); (p/'memory.max').write_text(str(64<<20)); roots.append(p)
    args=SimpleNamespace(worker='/profile/session-worker',residue='/profile/session-residue',bpf='/profile/cis.bpf.o')
    source=source_manifest(args,env['boot_id']); permit=prototype_admission.create(source,env,time.monotonic_ns())
    (out/'permit.json').write_text(json.dumps(permit,indent=2))
    (out/'plan.json').write_text(json.dumps(dict(order=order(),rounds=3,depth=4,release_delay_s=.05,
        window_ms=2000,fixture='blk_mq_alloc_request',source=source),indent=2))
    endpoint='/run/cis-tag.sock'; log=(out/'controller.log').open('x')
    daemon=subprocess.Popen(['/usr/bin/python3','/profile/session.py','--socket',endpoint,'--directory',str(out/'records'),
        '--worker',args.worker,'--residue',args.residue,'--bpf',args.bpf,'--admission-policy','prototype',
        '--prototype-permit',str(out/'permit.json'),'daemon'],stdout=log,stderr=log)
    request_log=(out/'requests.jsonl').open('x'); children=[]; results=[]; buffers={}; launchers={}
    wire=(out/'actor-wire.jsonl').open('x')

    def request(op,**kw):
        req=dict(version=1,op=op,**kw); before=time.monotonic_ns()
        with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as sock:
            sock.settimeout(15); sock.connect(endpoint); sock.send(json.dumps(req).encode()); answer=json.loads(sock.recv(8192))
        request_log.write(json.dumps(dict(before_ns=before,after_ns=time.monotonic_ns(),request=req,response=answer))+'\n'); request_log.flush()
        if not answer['ok']: raise RuntimeError(answer)
        return answer['data']

    def wait(sid,field):
        end=time.monotonic()+20
        while time.monotonic()<end:
            row=request('status',session=sid)
            if row.get(field): return row
            if row.get('finalized'): raise RuntimeError(row)
            time.sleep(.02 if field=='window' else .1)
        raise TimeoutError(sid)

    def line(child):
        fd=child.stdout.fileno(); end=time.monotonic()+5
        while True:
            data=buffers.get(fd,b'')
            while b'\n' not in data:
                if time.monotonic()>end: raise TimeoutError('fixture actor')
                if not select.select([fd],[],[],.1)[0]: continue
                chunk=os.read(fd,4096)
                if not chunk: raise RuntimeError(('actor EOF',child.poll(),data))
                data+=chunk
            raw,rest=data.split(b'\n',1); buffers[fd]=rest
            wire.write(json.dumps(dict(launcher=child.pid,line=raw.decode()))+'\n'); wire.flush()
            match=re.fullmatch(rb'CIS_SESSION_CONTAINER host_pid=(\d+)',raw)
            if match:
                if child.pid in launchers: raise ValueError('duplicate launcher pid')
                launchers[child.pid]=int(match[1]); continue
            return json.loads(raw)

    def command(child,op,disk=0,slot=0,nowait=0):
        child.stdin.write(('%d %d %d %d\n'%(op,disk,slot,nowait)).encode()); child.stdin.flush()
        if line(child)!={'event':'attempt'}: raise ValueError('actor attempt')

    try:
        end=time.monotonic()+10
        while not Path(endpoint).exists():
            if daemon.poll() is not None or time.monotonic()>end: raise RuntimeError('daemon readiness')
            time.sleep(.02)
        targets=[request('register',path=str(p))['target'] for p in roots]
        for label in order():
            case=label.split('-')[0]; collecting='-block-' in label; sid=None
            if collecting:
                sid=request('start',collector='block',targets=targets,nonce=label.replace('-',''),window_ms=2000)['session_id']
                window=wait(sid,'window')['window']; active=observe('block')
            else:
                now=time.monotonic_ns(); window=dict(start_ns=now,end_ns=now+2_000_000_000); active=observe(None)
            running=[]; truth=[]
            for i,p in enumerate(roots):
                fd=os.open('/dev/cis-tag-fixture',os.O_RDWR)
                try:
                    child=subprocess.Popen(['/session_launch',str(p),str(i),'/tag_workload',str(fd)],
                        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,pass_fds=(fd,),bufsize=0)
                finally: os.close(fd)
                children.append(child); running.append(child); buffers[child.stdout.fileno()]=b''
                if line(child)!={'event':'ready'}: raise ValueError('fixture readiness')
            while time.monotonic_ns()<window['start_ns']+100_000_000: time.sleep(.002)
            def result(i):
                row=line(running[i])
                if row.get('event')!='result': raise ValueError('fixture result')
                if row['tid']!=launchers.get(running[i].pid): raise ValueError('host task truth')
                row['actor']=i; truth.append(row)
                with (out/(label+'-truth.jsonl')).open('a') as f: f.write(json.dumps(row)+'\n')
                return row
            for slot in range(3 if case=='available' else 4):
                command(running[0],0,slot=slot)
                if result(0)['result']!=0: raise ValueError('could not fill tags')
            command(running[0],2); held=result(0)['held']
            command(running[1],0,disk=int(case=='private'),nowait=int(case=='nowait'))
            if case=='exhausted':
                time.sleep(.05)
                command(running[0],1); result(0)
            result(1)
            for child in running: child.stdin.close()
            codes=[child.wait(timeout=5) for child in running]
            for child in running: child.stdout.close()
            if codes!=[0,0]: raise ValueError(('fixture exits',codes))
            report=None; identities=None
            if sid:
                final=wait(sid,'finalized')
                record=json.loads((out/'records'/(sid+'.json')).read_text())
                report=analyze(record,(out/'records'/(sid+'.jsonl')).read_bytes())
                identities=[record['root_identities'][t] for t in targets]
                (out/(label+'-report.json')).write_text(json.dumps(report,indent=2))
                if not final.get('objects_absent'): raise ValueError('collector cleanup')
            evidence=dict(case=case,label=label,session_id=sid,targets=targets,window=window,truth=truth,
                          held_before=held,exit_codes=codes,active_sources=active,idle_sources=observe(None))
            evidence['result']=check(evidence,report,identities)
            (out/(label+'-evidence.json')).write_text(json.dumps(evidence,indent=2)); results.append(evidence)
            if evidence['result']['status']!='PASS': raise ValueError(evidence['result'])
        (out/'result.json').write_text(json.dumps(dict(status='PASS',source=source,states=results),indent=2))
    finally:
        # Closing the holder releases its native tags before terminating a waiter.
        for child in children:
            if child.poll() is None: child.terminate()
        for child in children:
            try: child.wait(timeout=5)
            except subprocess.TimeoutExpired: child.kill(); child.wait()
        if daemon.poll() is None: daemon.terminate()
        try: daemon.wait(timeout=15)
        except subprocess.TimeoutExpired: daemon.kill(); daemon.wait()
        request_log.close(); wire.close(); log.close()


if __name__=='__main__': run()
