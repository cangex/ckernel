#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Four active containers, two independent native fixture sources, fixed order."""
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
from joint_costs import snapshot as cost_snapshot
from mixed_vm_check import PLAN,order,roles,selected,verify_state
from net_vm import tcp_pair


def run():
    os.umask(0o077); os.sched_setaffinity(0,{7})
    env=admission.environment(); admission.check_environment(env)
    if Path('/sys/module/cis_observe/parameters/net_shift').read_text().strip()!='0': raise ValueError('full-rate network truth required')
    out=Path('/tmp/mixed-evidence'); out.mkdir(mode=0o700)
    root=Path('/sys/fs/cgroup/cis-mixed'); root.mkdir(); (root/'management').mkdir()
    (root/'management/cgroup.procs').write_text(str(os.getpid()))
    (root/'cgroup.subtree_control').write_text('+cpu +memory +cpuset +io')
    roots=[]
    for i in range(4):
        p=root/('root%d'%i); p.mkdir(); (p/'memory.max').write_text(str(PLAN['memory_max_bytes'])); roots.append(p)
    args=SimpleNamespace(worker='/profile/session-worker',residue='/profile/session-residue',bpf='/profile/cis.bpf.o')
    source=source_manifest(args,env['boot_id']); permit=admission.create(source,env,time.monotonic_ns())
    (out/'permit.json').write_text(json.dumps(permit,indent=2))
    hz=os.sysconf('SC_CLK_TCK')
    (out/'plan.json').write_text(json.dumps(dict(design=PLAN,order=order(),source=source,clock_ticks=hz),indent=2))
    endpoint='/run/cis-mixed.sock'; log=(out/'controller.log').open('x'); audit=(out/'requests.jsonl').open('x')
    daemon=subprocess.Popen(['/usr/bin/python3','/profile/session.py','--socket',endpoint,'--directory',str(out/'records'),
        '--worker',args.worker,'--residue',args.residue,'--bpf',args.bpf,'--admission-policy','prototype',
        '--prototype-permit',str(out/'permit.json'),'daemon'],stdout=log,stderr=log)
    children=[]; handles=[]; sockets=[]; descriptors=[]; labels=[]

    def request(op,**fields):
        before=time.monotonic_ns(); req=dict(version=1,op=op,**fields)
        with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as sock:
            sock.settimeout(15); sock.connect(endpoint); sock.send(json.dumps(req).encode()); reply=json.loads(sock.recv(16384))
        retained=reply
        if op=='status' and reply.get('ok'):
            retained=dict(reply,data={k:reply['data'][k] for k in ('state','session_id','finalized') if k in reply['data']})
        audit.write(json.dumps(dict(before_ns=before,after_ns=time.monotonic_ns(),request=req,response=retained))+'\n'); audit.flush()
        if not reply['ok']: raise RuntimeError(reply)
        return reply['data']

    def wait(sid,key):
        deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            row=request('status',session=sid)
            if row.get(key): return row
            if row.get('finalized'): raise ValueError(row)
            time.sleep(.02 if key=='window' else .1)
        raise TimeoutError(key)

    def snapshot():
        result=cost_snapshot(root,roots)
        result['net_source_audit']=Path('/sys/kernel/debug/cis_net_audit').read_text()
        result['read_end_ns']=time.monotonic_ns()
        return result

    def launch(label,kind,actor,root_index,cpu,command,fd=None):
        h=(out/(label+'-'+kind+str(actor)+'.log')).open('x'); handles.append(h)
        child=subprocess.Popen(['/session_launch',str(roots[root_index]),str(cpu)]+command,
            stdout=h,stderr=h,pass_fds=() if fd is None else (fd,))
        children.append(child); return child

    try:
        deadline=time.monotonic()+10
        while not Path(endpoint).exists():
            if daemon.poll() is not None or time.monotonic()>deadline: raise RuntimeError('mixed daemon readiness')
            time.sleep(.02)
        registered=[request('register',path=str(p))['target'] for p in roots]
        descriptors=[os.open(p,os.O_RDWR|os.O_DIRECT|os.O_CLOEXEC) for p in PLAN['devices']]
        for case,r,mode in order():
            label='%s-%s%d'%(case,mode,r); network,block=roles(r)
            client,server=tcp_pair(); sockets.extend((client,server)); net_fds=[server,server]
            if case=='private':
                other_client,other_server=tcp_pair(); sockets.extend((other_client,other_server)); net_fds[1]=other_server
            block_fds=[descriptors[0],descriptors[0] if case=='shared' else descriptors[1]]
            before=snapshot(); start=time.monotonic_ns()+500_000_000
            ordinary=[launch(label,'ordinary',i,i,PLAN['ordinary_cpus'][i],
                ['/joint_workload',PLAN['ordinary_workloads'][i],str(start)]) for i in range(4)]
            time.sleep(max(0,(start-time.monotonic_ns())/1e9)+.15)
            if any(p.poll() is not None for p in ordinary): raise ValueError('ordinary early exit')
            targets=[registered[i] for i in selected(r,mode)]; sid=None; record=None; capture=None
            if mode!='off':
                sid=request('start',collector=mode,targets=targets,nonce=label.replace('-',''),window_ms=2000)['session_id']
                window=wait(sid,'window')['window']; active=observe(mode)
            else:
                now=time.monotonic_ns(); window=dict(start_ns=now,end_ns=now+2_000_000_000); active=observe(None)
            fixture_start=max(window['start_ns']+300_000_000,time.monotonic_ns()+100_000_000)
            fixture=[]
            for i in range(2):
                fd=net_fds[i].fileno()
                fixture.append(launch(label,'net',i,network[i],i,
                    ['/net_workload',str(fd),str(i),str(fixture_start),case],fd))
                fd=block_fds[i]
                fixture.append(launch(label,'block',i,block[i],i,
                    ['/block_workload',str(fd),str(i),str(fixture_start+PLAN['block_offset_ns'])],fd))
            fixture_codes=[p.wait(timeout=10) for p in fixture]
            if sid:
                done=wait(sid,'finalized')
                record=json.loads((out/'records'/(sid+'.json')).read_text())
                capture=(out/'records'/(sid+'.jsonl')).read_bytes()
                if not done.get('objects_absent'): raise ValueError('mixed capture cleanup')
            idle=observe(None)
            ordinary_codes=[p.wait(timeout=10) for p in ordinary]
            after=snapshot()
            ev=dict(label=label,case=case,round=r,mode=mode,session_id=sid,registered=registered,
                targets=targets,network_roots=network,block_roots=block,start_ns=start,window=window,
                before=before,after=after,ordinary_exit_codes=ordinary_codes,fixture_exit_codes=fixture_codes,
                active_sources=active,idle_sources=idle)
            (out/(label+'-evidence.json')).write_text(json.dumps(ev,indent=2))
            read=lambda kind,n:[(out/(label+'-'+kind+str(i)+'.log')).read_text() for i in range(n)]
            checked=verify_state(ev,read('ordinary',4),read('net',2),read('block',2),record,capture,hz)
            (out/(label+'-verified.json')).write_text(json.dumps(checked,indent=2)); labels.append(label)
            for sock in sockets: sock.close()
            sockets.clear()
        (out/'result.json').write_text(json.dumps(dict(status='PASS_SCOPED',source=source,labels=labels),indent=2))
    finally:
        for p in children:
            if p.poll() is None: p.terminate()
        for p in children:
            try: p.wait(timeout=5)
            except subprocess.TimeoutExpired: p.kill(); p.wait()
        for sock in sockets: sock.close()
        for fd in descriptors: os.close(fd)
        if daemon.poll() is None: daemon.terminate()
        try: daemon.wait(timeout=15)
        except subprocess.TimeoutExpired: daemon.kill(); daemon.wait()
        for h in handles: h.close()
        audit.close(); log.close()


if __name__=='__main__': run()
