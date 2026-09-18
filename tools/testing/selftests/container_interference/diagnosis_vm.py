#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Real IP/PSI -> bounded queue -> specialist test, with unmodified clocks."""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time
from types import SimpleNamespace

import prototype_admission as admission
from session import source_manifest
from session_quality import assess
from source_switches import observe
from unified_report import analyze,markdown


def run():
    os.umask(0o077); os.sched_setaffinity(0,{7})
    env=admission.environment(); admission.check_environment(env)
    out=Path('/tmp/diagnosis-evidence'); out.mkdir(mode=0o700)
    root=Path('/sys/fs/cgroup/cis-diagnosis'); root.mkdir(); (root/'management').mkdir()
    (root/'management/cgroup.procs').write_text(str(os.getpid()))
    (root/'cgroup.subtree_control').write_text('+cpu +memory +cpuset')
    roots=[]
    for i in range(2):
        p=root/('root%d'%i); p.mkdir(); (p/'memory.max').write_text(str(64<<20)); roots.append(p)
    args=SimpleNamespace(worker='/profile/session-worker',residue='/profile/session-residue',bpf='/profile/cis.bpf.o')
    source=source_manifest(args,env['boot_id']); permit=admission.create(source,env,time.monotonic_ns())
    (out/'permit.json').write_text(json.dumps(permit,indent=2))
    plan=dict(schema='cis-x6-plan-v1',source=source,interval_s=60,window_ms=2000,min_samples=32,
        primary_cpu=[0,1],competitor_cpu=[1,0],management_cpu=7,deadline_seconds=700,
        auto_per_permit=2,ordinary_after_specialist=True,no_fake_clock=True,
        workload='getpid system calls, followed by independent CPU-only competitors in opposite container',
        expected_collector='sched',p99_acceptance='NOT_MEASURED_FUNCTIONAL_CONTROL_TEST')
    (out/'plan.json').write_text(json.dumps(plan,indent=2))
    endpoint='/run/cis-diagnosis.sock'; log=(out/'controller.log').open('x')
    command=['/usr/bin/python3','/profile/session.py','--socket',endpoint,'--directory',str(out/'records'),
        '--worker',args.worker,'--residue',args.residue,'--bpf',args.bpf,'--admission-policy','prototype',
        '--prototype-permit',str(out/'permit.json'),'daemon']
    daemon=subprocess.Popen(command,stdout=log,stderr=log)
    audit=(out/'requests.jsonl').open('x'); children=[]; handles=[]; cases=[]; records={}; pidfds=[]

    def request(op,rejected=False,**fields):
        message=dict(version=1,op=op,**fields); before=time.monotonic_ns()
        with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as sock:
            sock.settimeout(15); sock.connect(endpoint); sock.send(json.dumps(message).encode()); answer=json.loads(sock.recv(16384))
        retained=answer
        if op=='status' and answer.get('ok'):
            # Full immutable records already have a separate artifact. Avoid
            # repeating source manifests on every idle readiness poll.
            retained=dict(answer,data={k:answer['data'][k] for k in
                ('state','session_id','finalized','prototype_sessions_started') if k in answer['data']})
        audit.write(json.dumps(dict(before_ns=before,after_ns=time.monotonic_ns(),request=message,response=retained))+'\n'); audit.flush()
        if answer['ok'] is rejected: raise RuntimeError(answer)
        return answer if rejected else answer['data']

    def note(name,**data):
        cases.append(dict(name=name,time_ns=time.monotonic_ns(),status='PASS',**data))
        (out/'checks.json').write_text(json.dumps(cases,indent=2))

    def finish(sid):
        limit=time.monotonic()+20
        while time.monotonic()<limit:
            row=request('status',session=sid)
            if row.get('finalized'):
                row=json.loads((out/'records'/(sid+'.json')).read_text())
                if assess(row)['status']!='PASS': raise ValueError(assess(row))
                records[sid]=row
                report=analyze(row,(out/'records'/(sid+'.jsonl')).read_bytes())
                (out/(sid+'-explanation.json')).write_text(json.dumps(report,indent=2))
                (out/(sid+'-explanation.md')).write_text(markdown(report))
                return row
            time.sleep(.1)
        raise TimeoutError('session did not finish')

    def free_slot():
        sched=request('schedule_status'); last=sched.get('last_admit_ns')
        if last is not None: time.sleep(max(0,(last+60_000_000_000-time.monotonic_ns())/1e9)+.1)

    def launch(role,mode,cpu):
        path=out/('%s-%d.log'%(mode,role)); handle=path.open('x'); handles.append(handle)
        p=subprocess.Popen(['/session_launch',str(roots[role]),str(cpu),'/diagnosis_workload',mode,'680',str(time.monotonic_ns()+100_000_000)],
            stdout=handle,stderr=handle); children.append(p)
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            lines=[v for v in path.read_text().splitlines() if v.startswith('CIS_SESSION_CONTAINER host_pid=')]
            if len(lines)==1:
                pid=int(lines[0].split('=')[1]); fd=os.pidfd_open(pid)
                try:
                    parent=int(Path('/proc/%d/stat'%pid).read_text().rsplit(')',1)[1].split()[1])
                    cg=Path('/proc/%d/cgroup'%pid).read_text().strip()
                    if parent!=p.pid or cg!='0::'+str(roots[role]).removeprefix('/sys/fs/cgroup'):
                        raise ValueError('test child provenance changed')
                except BaseException: os.close(fd); raise
                pidfds.append((p,fd)); break
            if p.poll() is not None: raise ValueError('workload failed before readiness')
            time.sleep(.01)
        else: raise TimeoutError('workload PID acknowledgement')
        return p.pid

    try:
        limit=time.monotonic()+10
        while not Path(endpoint).exists():
            if daemon.poll() is not None or time.monotonic()>limit: raise RuntimeError('daemon readiness')
            time.sleep(.02)
        targets=[request('register',path=str(p))['target'] for p in roots]
        # Capability readiness is established by a real same-source collection.
        sid=request('start',collector='sched',targets=targets,nonce='ready')['session_id']; finish(sid)
        request('schedule_configure',plan=dict(interval_s=60,jitter_ms=0,min_samples=32))
        epoch=request('status')['nonce_epoch']
        pids=[launch(i,'syscalls',i) for i in range(2)]; time.sleep(1)
        sid=request('start',collector='ip',targets=targets,nonce='reference',nonce_epoch=epoch)['session_id']
        reference=finish(sid)
        assert all(v['valid'] for v in reference['survey']['roots'].values()), reference['survey']
        note('real_reference',session=sid,pids=pids)
        pids=[launch(i,'cpu',1-i) for i in range(2)]; time.sleep(1)
        free_slot()
        sid=request('start',collector='ip',targets=targets,nonce='pressure',nonce_epoch=epoch)['session_id']
        pressure=finish(sid); queue=request('diagnosis_status')
        candidates=[v for v in queue['items'] if v['collector']=='sched' and v.get('automatic_eligible')]
        assert len(candidates)==2 and not queue['enabled'], dict(queue=queue,survey=pressure['survey'])
        note('real_pressure_to_two_candidates',session=sid,pids=pids,candidates=candidates)
        request('diagnosis_run',rejected=True,candidate_id=candidates[0]['candidate_id'])
        note('manual_shares_host_interval')
        free_slot()
        sid=request('diagnosis_run',candidate_id=candidates[0]['candidate_id'])['session_id']; manual=finish(sid)
        assert manual['scheduled']['kind']=='manual_diagnosis'
        assert manual['targets']==[candidates[0]['target']]
        note('manual_diagnosis',session=sid)
        request('diagnosis_auto',enabled=True); request('schedule_enable')
        complete=[]; limit=time.monotonic()+440
        while time.monotonic()<limit and len(complete)<6:
            status=request('status')
            if status['state']=='FAULTED': raise ValueError(status)
            for session in status['sessions']:
                if session in records: continue
                row=request('status',session=session)
                if row.get('finalized'):
                    row=finish(session); complete.append(row)
                    note('scheduled_%d'%len(complete),session=session,collector=row['collector'],scheduled=row['scheduled'])
            time.sleep(.25)
        request('schedule_pause'); state=request('diagnosis_status')
        automatic=[r for r in complete if r['scheduled'].get('kind')=='automatic_diagnosis']
        assert len(complete)==6 and len(automatic)==2 and state['auto_started']==2, (complete,state)
        assert complete[0]['collector']=='ip'
        for i,r in enumerate(complete):
            if r['collector']!='ip':
                assert r['collector']=='sched' and i>0 and complete[i-1]['collector']=='ip'
        assert automatic[0]['targets']!=manual['targets'], 'least recently served target was skipped'
        assert len({r['targets'][0] for r in automatic})==2
        note('automatic_fairness_and_two_session_limit',sessions=[r['session_id'] for r in automatic],queue=state)
        request('survey_epoch'); assert not request('diagnosis_status')['items']; note('epoch_removes_candidates')
        count=request('status')['prototype_sessions_started']; request('stop'); assert daemon.wait(timeout=15)==0
        daemon=subprocess.Popen(command,stdout=log,stderr=log); limit=time.monotonic()+10
        while time.monotonic()<limit:
            try:
                status=request('status'); break
            except (ConnectionRefusedError,FileNotFoundError): time.sleep(.05)
        state=request('diagnosis_status')
        assert not state['enabled'] and not state['items'] and state['auto_started']==2
        assert status['prototype_sessions_started']==count
        note('restart_preserves_auto_budget_but_pauses',queue=state)
        completed=dict(schema='cis-x6-result-v1',status='PASS',source=source,
            checks=cases,sessions=list(records),idle_sources=observe(None))
    finally:
        for p,fd in pidfds:
            if p.poll() is None:
                try: signal.pidfd_send_signal(fd,signal.SIGTERM)
                except ProcessLookupError: pass
        covered={p for p,fd in pidfds}
        for p in children:
            if p not in covered and p.poll() is None: p.terminate()
        exits=[]
        for p in children:
            try: exits.append(p.wait(timeout=5))
            except subprocess.TimeoutExpired: p.kill(); exits.append(p.wait())
        (out/'workload-exits.json').write_text(json.dumps(exits))
        for p,fd in pidfds: os.close(fd)
        if daemon.poll() is None: daemon.terminate()
        try: daemon.wait(timeout=15)
        except subprocess.TimeoutExpired: daemon.kill(); daemon.wait()
        for h in handles: h.close()
        audit.close(); log.close()
    if exits!=[0]*4: raise ValueError(('workload did not exit correctly',exits))
    (out/'result.json').write_text(json.dumps(completed,indent=2))


if __name__=='__main__': run()
