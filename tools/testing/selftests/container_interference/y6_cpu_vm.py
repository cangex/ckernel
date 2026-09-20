#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
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
from cpu_report import analyze
from y6_cpu_check import CASES,order,check


def run():
    os.umask(0o077); os.sched_setaffinity(0,{7})
    env=admission.environment(); admission.check_environment(env)
    if not Path('/cis-disposable-vm').exists(): raise PermissionError('disposable VM required')
    out=Path('/tmp/y6-cpu-evidence'); out.mkdir(mode=0o700)
    endpoint='/run/cis-y6-cpu.sock'; children=[]; handles=[]; daemon=None
    requests=(out/'requests.jsonl').open('x'); log=(out/'controller.log').open('x')
    def request(op,**fields):
        req=dict(version=1,op=op,**fields); begin=time.monotonic_ns()
        with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as sock:
            sock.settimeout(15); sock.connect(endpoint); sock.send(json.dumps(req).encode()); reply=json.loads(sock.recv(16384))
        kept=reply
        if op=='status' and reply.get('ok'):
            kept=dict(reply,data={k:reply['data'][k] for k in ('state','session_id','finalized') if k in reply['data']})
        requests.write(json.dumps(dict(before_ns=begin,after_ns=time.monotonic_ns(),request=req,response=kept))+'\n'); requests.flush()
        if not reply['ok']: raise RuntimeError(reply)
        return reply['data']
    def wait(sid,field):
        deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            r=request('status',session=sid)
            if r.get(field): return r
            if r.get('finalized'): raise RuntimeError(r)
            time.sleep(.02 if field=='window' else .1)
        raise TimeoutError(sid)
    roots=[]
    def snapshot():
        return dict(before_ns=time.monotonic_ns(),proc_stat=Path('/proc/stat').read_text(),
            memory=Path('/proc/meminfo').read_text(),softirqs=Path('/proc/softirqs').read_text(),
            interrupts=Path('/proc/interrupts').read_text(),
            roots=[{n:(p/n).read_text() for n in ('cpu.stat','cpu.max','cpu.pressure','memory.current','memory.peak','memory.events')} for p in roots],
            after_ns=time.monotonic_ns())
    try:
        root=Path('/sys/fs/cgroup/cis-y6-cpu'); root.mkdir(); (root/'management').mkdir()
        (root/'management/cgroup.procs').write_text(str(os.getpid()))
        (root/'cgroup.subtree_control').write_text('+cpu +memory +cpuset')
        for i in range(2):
            p=root/('root%d'%i); p.mkdir(); (p/'memory.max').write_text(str(64<<20)); roots.append(p)
        args=SimpleNamespace(worker='/profile/session-worker',residue='/profile/session-residue',bpf='/profile/cis.bpf.o')
        source=source_manifest(args,env['boot_id']); permit=admission.create(source,env,time.monotonic_ns())
        (out/'permit.json').write_text(json.dumps(permit,indent=2))
        devices=sorted(p.name for p in Path('/sys/bus/event_source/devices').iterdir())
        plan=dict(schema='cis-y6-cpu-plan-v1',order=order(),cases=CASES,source=source,window_ms=2000,
            cpus=[0,1],management_cpu=7,hardware_sources=devices,
            schedstats=Path('/proc/sys/kernel/sched_schedstats').read_text().strip(),
            spe='UNSUPPORTED' if not any('spe' in n.lower() for n in devices) else 'NOT_VALIDATED',
            pmu_contention='NOT_CLAIMED',tail_latency='Y7_PENDING',background_origin='UNKNOWN')
        (out/'plan.json').write_text(json.dumps(plan,indent=2))
        daemon=subprocess.Popen(['/usr/bin/python3','/profile/session.py','--socket',endpoint,'--directory',str(out/'records'),
            '--worker',args.worker,'--residue',args.residue,'--bpf',args.bpf,'--admission-policy','prototype',
            '--prototype-permit',str(out/'permit.json'),'daemon'],stdout=log,stderr=log)
        deadline=time.monotonic()+10
        while not Path(endpoint).exists():
            if daemon.poll() is not None or time.monotonic()>deadline: raise RuntimeError('readiness')
            time.sleep(.02)
        targets=[request('register',path=str(p))['target'] for p in roots]; states=[]
        for entry in order():
            label=entry['label']; name=entry['case']; sid=None
            for i,p in enumerate(roots): (p/'cpu.max').write_text('20000 100000' if name=='quota' and not i else 'max 100000')
            before=snapshot()
            if entry['enabled']:
                sid=request('start',collector='cpu',cpus=[0,1],targets=targets,nonce=label,window_ms=2000)['session_id']
                window=wait(sid,'window')['window']; active=observe('cpu')
            else:
                t=time.monotonic_ns(); window=dict(start_ns=t,end_ns=t+2_000_000_000); active=observe(None)
            start=max(window['start_ns']+400_000_000,time.monotonic_ns()+100_000_000); running=[]
            for i,p in enumerate(roots):
                h=(out/(label+'-%d.log'%i)).open('x'); handles.append(h)
                child=subprocess.Popen(['/session_launch',str(p),str(CASES[name][i]),'/cpu_workload',str(i),name,str(start)],stdout=h,stderr=h)
                children.append(child); running.append(child)
            codes=[p.wait(timeout=10) for p in running]
            record=None; raw=None
            if sid:
                wait(sid,'finalized'); record=json.loads((out/'records'/(sid+'.json')).read_text())
                raw=(out/'records'/(sid+'.jsonl')).read_bytes()
                (out/(label+'-report.json')).write_text(json.dumps(analyze(record,raw),indent=2))
            else: time.sleep(max(0,(window['end_ns']-time.monotonic_ns())/1e9))
            idle=observe(None); after=snapshot()
            evidence=dict(**entry,session_id=sid,targets=targets,window=window,before=before,after=after,
                active_sources=active,idle_sources=idle,exit_codes=codes)
            checked=check(evidence,[(out/(label+'-%d.log'%i)).read_text() for i in range(2)],record,raw)
            evidence['result']=checked; states.append(evidence)
            (out/(label+'-evidence.json')).write_text(json.dumps(evidence,indent=2))
            (out/'partial.json').write_text(json.dumps(states,indent=2))
            if checked['status']!='PASS_SCOPED': raise ValueError(checked)
        (out/'result.json').write_text(json.dumps(dict(status='PASS_SCOPED',source=source,states=states),indent=2))
    finally:
        for p in children:
            if p.poll() is None: p.terminate()
        for p in children:
            try: p.wait(timeout=5)
            except subprocess.TimeoutExpired: p.kill(); p.wait()
        if daemon is not None:
            if daemon.poll() is None: daemon.terminate()
            try: daemon.wait(timeout=15)
            except subprocess.TimeoutExpired: daemon.kill(); daemon.wait()
        for h in handles: h.close()
        requests.close(); log.close()

if __name__=='__main__': run()
