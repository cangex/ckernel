#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Bounded native rwsem truth; no hand-written observation events."""
import argparse
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
from rwsem_report import analyze
from owner_report import fields
from joint_costs import snapshot
from rwsem_joint import PLAN as JOINT_PLAN, roles as joint_roles, verify as verify_joint

CASES=('writeRead','writeWrite','readers','private','tryFailure','abort','nonOwner','preWindow','reuse','downgrade')


def run(overflow=False, joint=False):
    if overflow and joint: raise ValueError('overflow is a separate cohort')
    os.umask(0o077); os.sched_setaffinity(0,{7})
    env=admission.environment(); admission.check_environment(env)
    out=Path('/tmp/rwsem-evidence'); out.mkdir(mode=0o700)
    root=Path('/sys/fs/cgroup/cis-rwsem'); root.mkdir(); (root/'management').mkdir()
    (root/'management/cgroup.procs').write_text(str(os.getpid()))
    (root/'cgroup.subtree_control').write_text('+cpu +memory +cpuset')
    roots=[]
    for i in range(4):
        p=root/('root%d'%i); p.mkdir(); (p/'memory.max').write_text(str(64<<20)); roots.append(p)
    args=SimpleNamespace(worker='/profile/session-worker',residue='/profile/session-residue',bpf='/profile/cis.bpf.o')
    source=source_manifest(args,env['boot_id']); permit=admission.create(source,env,time.monotonic_ns())
    (out/'permit.json').write_text(json.dumps(permit,indent=2))
    cases=['overflow'] if overflow else list(CASES)
    selected=[]
    for slot in (0,1):
        query=subprocess.run(['/container-root/rwsem_workload','query',str(slot)],check=True,capture_output=True,text=True)
        (out/('object-query-%d.log'%slot)).write_text(query.stdout)
        row=fields(query.stdout)
        if row['slot']!=slot or not row['object']: raise ValueError('fixture selection')
        selected.append(row['object'])
    plan=dict(schema='cis-rwsem-vm-plan-v1',cases=cases,rounds=3,source=source,window_ms=2000,
        target_indices=[0,1],registered_roots=4,cpus=[0,1,2,3],hold_ms=200,extended_hold_ms=500,
        eligible_min_overlap_ns=1_000_000,reader_limit=8,selected_objects=selected,off_on_order='OFF_ON,ON_OFF,OFF_ON',
        scope='native public rwsem fixture only; no production or full-kernel coverage claim')
    if joint:
        plan['joint'] = JOINT_PLAN
        plan['clock_ticks'] = os.sysconf('SC_CLK_TCK')
    (out/'plan.json').write_text(json.dumps(plan,indent=2))
    endpoint='/run/cis-rwsem.sock'; log=(out/'controller.log').open('x'); requests=(out/'requests.jsonl').open('x')
    daemon=subprocess.Popen(['/usr/bin/python3','/profile/session.py','--socket',endpoint,'--directory',str(out/'records'),
        '--worker',args.worker,'--residue',args.residue,'--bpf',args.bpf,'--admission-policy','prototype',
        '--prototype-permit',str(out/'permit.json'),'daemon'],stdout=log,stderr=log)
    children=[]; handles=[]; states=[]; token=0
    role_map=list(range(4))

    def request(op,**kw):
        req=dict(version=1,op=op,**kw); before=time.monotonic_ns()
        with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as sock:
            sock.settimeout(15); sock.connect(endpoint); sock.send(json.dumps(req).encode()); reply=json.loads(sock.recv(16384))
        retained=reply
        if op=='status' and reply.get('ok'):
            retained=dict(reply,data={k:reply['data'][k] for k in ('state','session_id','finalized','prototype_sessions_started') if k in reply['data']})
        requests.write(json.dumps(dict(before_ns=before,after_ns=time.monotonic_ns(),request=req,response=retained))+'\n'); requests.flush()
        if not reply['ok']: raise RuntimeError(reply)
        return reply['data']

    def wait(sid,key):
        deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            r=request('status',session=sid)
            if r.get(key): return r
            if r.get('finalized'): raise RuntimeError(r)
            time.sleep(.02 if key=='window' else .1)
        raise TimeoutError(sid)

    def launch(label,actor,reset=False,slot=0,mode=0,hold=0,wait_slot=0,wait_holders=0):
        handle=(out/(label+'.log')).open('x'); handles.append(handle)
        p=subprocess.Popen(['/session_launch',str(roots[actor]),str(actor),'/rwsem_workload',
            'reset' if reset else 'operate',str(slot),str(token),str(mode),str(hold),str(wait_slot),str(wait_holders)],
            stdout=handle,stderr=handle)
        children.append(p); return p

    def finished(p):
        rc=p.wait(timeout=5)
        if rc: raise RuntimeError('workload failed: '+str(rc))

    try:
        deadline=time.monotonic()+10
        while not Path(endpoint).exists():
            if daemon.poll() is not None or time.monotonic()>deadline: raise RuntimeError('daemon readiness')
            time.sleep(.02)
        registered=[request('register',path=str(p))['target'] for p in roots]
        targets=registered[:2]; observe(None)
        for repeat in range(3):
            role_map=joint_roles(repeat) if joint else list(range(4))
            targets=[registered[i] for i in role_map[:2]]
            for case in cases:
                for enabled in ((False,True) if repeat%2==0 else (True,False)):
                    label='%s%d-%s'%(case,repeat,'on' if enabled else 'off'); token+=1
                    logs=[]; jobs=[]; sid=None; active=None; window=None
                    ordinary=[]; joint_info=None
                    if joint:
                        before=snapshot(root, roots)
                        ordinary_start=time.monotonic_ns()+500_000_000
                        ordinary_logs=[]
                        for i in range(4):
                            name=label+'-ordinary-%d.log'%i
                            handle=(out/name).open('x'); handles.append(handle); ordinary_logs.append(name)
                            proc=subprocess.Popen(['/session_launch',str(roots[i]),str(JOINT_PLAN['ordinary_cpus'][i]),
                                '/joint_workload',JOINT_PLAN['ordinary_workloads'][i],str(ordinary_start)],stdout=handle,stderr=handle)
                            children.append(proc); ordinary.append(proc)
                        time.sleep(max(0,(ordinary_start-time.monotonic_ns())/1e9)+.15)
                        if any(p.poll() is not None for p in ordinary): raise ValueError('ordinary business exited early')
                        joint_info=dict(start_ns=ordinary_start,logs=ordinary_logs,before=before)
                    fixture_begin=len(children)
                    def start(suffix,actor,**kw):
                        actor=role_map[actor]
                        name=label+'-'+suffix; logs.append(name+'.log')
                        jobs.append(dict(log=name+'.log',actor_index=actor,token=token,arguments=kw))
                        return launch(name,actor,**kw)
                    def reset_slots():
                        for slot in (0,1): finished(start('reset%d-%d'%(slot,token),0,reset=True,slot=slot))
                    if case=='preWindow':
                        reset_slots(); holder=start('holder',0,mode=1,hold=500); time.sleep(.08)
                        if holder.poll() is not None: raise RuntimeError('pre-window holder absent')
                    if enabled:
                        sid=request('start',collector='rwsem',targets=targets,objects=selected,nonce=label.replace('-',''),window_ms=2000)['session_id']
                        window=wait(sid,'window')['window']; active=observe('rwsem')
                        delay=(window['start_ns']+20_000_000-time.monotonic_ns())/1e9
                        if delay>0: time.sleep(delay)
                    else: active=observe(None)
                    if case!='preWindow': reset_slots()
                    if case=='readers':
                        start('holder0',0,mode=0,hold=200); start('holder2',2,mode=0,hold=200)
                        start('waiter',1,mode=1,wait_holders=2)
                    elif case=='overflow':
                        for n in range(10): start('holder%d'%n,(0,2,3)[n%3],mode=0,hold=500)
                        start('waiter',1,mode=1,wait_holders=10)
                    elif case=='reuse':
                        a=start('holder0',0,mode=1,hold=200); b=start('waiter0',1,mode=0,wait_holders=1)
                        finished(a); finished(b); token+=1; reset_slots()
                        start('holder1',0,mode=1,hold=200); start('waiter1',1,mode=0,wait_holders=1)
                    else:
                        if case!='preWindow': start('holder',0,mode=4 if case=='nonOwner' else 5 if case=='downgrade' else 1,hold=200)
                        start('waiter',1,slot=1 if case=='private' else 0,
                            mode=1 if case in ('writeWrite','nonOwner','downgrade') else 2 if case=='tryFailure' else 6 if case=='abort' else 0,
                            wait_slot=0,wait_holders=1)
                    for p in children[fixture_begin:]: finished(p)
                    if enabled and time.monotonic_ns()>=window['end_ns']: raise RuntimeError('truth outside window')
                    record=None; report=None
                    if enabled:
                        row=wait(sid,'finalized'); record=json.loads((out/'records'/(sid+'.json')).read_text())
                        report=analyze(record,(out/'records'/(sid+'.jsonl')).read_bytes())
                        (out/(label+'-report.json')).write_text(json.dumps(report,indent=2))
                        if not row.get('objects_absent'): raise RuntimeError('collector cleanup')
                    idle=observe(None)
                    if joint:
                        for p in ordinary: finished(p)
                        joint_info.update(after=snapshot(root, roots),exit_codes=[p.returncode for p in ordinary])
                    state=dict(label=label,case=case,round=repeat,enabled=enabled,session_id=sid,logs=logs,jobs=jobs,
                        registered=registered,targets=targets,active_sources=active,idle_sources=idle,
                        exit_codes=[p.returncode for p in children[fixture_begin:]],
                        quality=report['quality']['status'] if report else None)
                    if joint: state['joint']=joint_info
                    states.append(state); (out/(label+'-evidence.json')).write_text(json.dumps(state,indent=2))
                    (out/'partial.json').write_text(json.dumps(states,indent=2))
                    if joint:
                        verify_joint(plan['joint'],state,{name:(out/name).read_text() for name in joint_info['logs']},
                                     record,plan['clock_ticks'])
                    if enabled and report['quality']['status']!='PASS': raise RuntimeError(report['quality'])
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


if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('--overflow',action='store_true')
    p.add_argument('--joint',action='store_true'); a=p.parse_args(); run(a.overflow,a.joint)
