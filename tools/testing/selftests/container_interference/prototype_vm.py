#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Frozen bounded owner cases and six real periodic slots, no cost certification."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import time
from types import SimpleNamespace

import prototype_admission
from session import source_manifest
from explain import explain, markdown
from session_quality import assess
from explanation_check import check_owner


def run(specialists=False, bridge=False, costs=False):
    os.umask(0o077)
    env=prototype_admission.environment()
    prototype_admission.check_environment(env)
    os.sched_setaffinity(0,{7})
    out=Path('/tmp/prototype-evidence');out.mkdir(mode=0o700)
    root=Path('/sys/fs/cgroup/cis-prototype');root.mkdir()
    (root/'management').mkdir();(root/'management/cgroup.procs').write_text(str(os.getpid()))
    (root/'cgroup.subtree_control').write_text('+cpu +memory +cpuset')
    args=SimpleNamespace(worker='/profile/session-worker',residue='/profile/session-residue',bpf='/profile/cis.bpf.o')
    manifest=source_manifest(args,env['boot_id'])
    permit=prototype_admission.create(manifest,env,time.monotonic_ns())
    (out/'permit.json').write_text(json.dumps(permit,indent=2))
    plan=dict(owner_cases=['shared','private','reuse','preempt','nonTargetHolder'],
              periodic_slots=6,interval_s=60,window_ms=2000,roots=2,
              workload_seconds=385,performance_certification='NOT_ACCEPTED')
    if specialists:
        plan=dict(cases=['sched-shared','sched-private','sched-idle','reclaim-high',
                         'reclaim-control','quota'],window_ms=2000,roots=2,
                  memory_high_release='after completed capture, before business drain',
                  performance_certification='NOT_ACCEPTED')
    if bridge:
        plan=dict(cases=['dentryShared','dentryPrivate','fileShared','filePrivate','unregisteredHolder'],
                  window_ms=2000,roots=2,performance_certification='NOT_ACCEPTED')
    if costs:
        plan=dict(pairs=3,modes=['off','ip','owner','sched','reclaim'],workloads=['throughput','open-loop'],
                  seconds=4,window_ms=2000,role_rotation=True,performance_certification='NOT_ACCEPTED')
    (out/'plan.json').write_text(json.dumps(plan,indent=2))
    endpoint='/run/cis-prototype.sock'
    command=['/usr/bin/python3','/profile/session.py','--socket',endpoint,'--directory',str(out/'records'),
             '--worker',args.worker,'--residue',args.residue,'--bpf',args.bpf,
             '--admission-policy','prototype','--prototype-permit',str(out/'permit.json'),'daemon']
    controller_log=(out/'controller.log').open('x')
    daemon=subprocess.Popen(command,stdout=controller_log,stderr=controller_log)
    children=[];logs=[];sequence=0;results=[]
    audit=(out/'requests.jsonl').open('x')

    def request(op, tolerate=False, **fields):
        nonlocal sequence
        before=time.monotonic_ns();req=dict(version=1,op=op,**fields)
        with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as connection:
            connection.settimeout(15);connection.connect(endpoint)
            connection.send(json.dumps(req).encode());response=json.loads(connection.recv(8192))
        sequence+=1
        audit.write(json.dumps(dict(sequence=sequence,before_ns=before,after_ns=time.monotonic_ns(),request=req,response=response))+'\n')
        audit.flush()
        if not tolerate and not response['ok']:raise RuntimeError(response)
        return response if tolerate else response['data']

    def wait_socket():
        deadline=time.monotonic()+10
        while not Path(endpoint).exists():
            if daemon.poll() is not None or time.monotonic()>deadline:raise RuntimeError('daemon not ready')
            time.sleep(.02)

    def wait_window(sid):
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            row=request('status',session=sid)
            if row.get('window'):return row['window']['start_ns']
            if row.get('finalized'):raise RuntimeError(row)
            time.sleep(.005)
        raise TimeoutError('window')

    def finish(sid):
        deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            row=request('status',session=sid)
            if row.get('finalized'):
                if row['state']!='IDLE' or not row.get('objects_absent'):raise RuntimeError(row)
                full=json.loads((out/'records'/(sid+'.json')).read_text())
                report=explain(full,(out/'records'/(sid+'.jsonl')).read_bytes())
                (out/(full['nonce']+'-explain.json')).write_text(json.dumps(report,ensure_ascii=False,indent=2))
                (out/(full['nonce']+'-explain.md')).write_text(markdown(report))
                results.append(dict(nonce=full['nonce'],session_id=sid,quality=report['quality'],
                                    findings=report['finding_count'],result=full['result']))
                return full,report
            time.sleep(.02)
        raise TimeoutError(sid)

    def launch(label,i,command,cpu=None):
        log=(out/('%s-%d.log'%(label,i))).open('x');logs.append(log)
        child=subprocess.Popen(['/session_launch',str(root/('root%d'%i)),str(i*2 if cpu is None else cpu),'/workload']+command,
                               stdout=log,stderr=log)
        children.append(child);return child

    try:
        wait_socket();targets=[]
        for i in range(2):
            path=root/('root%d'%i);path.mkdir()
            targets.append(request('register',path=str(path))['target'])
        if bridge:
            for label in plan['cases']:
                if label=='unregisteredHolder':request('unregister',target=targets[1])
                selected=targets[:1] if label=='unregisteredHolder' else targets
                sid=request('start',collector='owner',targets=selected,nonce=label,window_ms=2000)['session_id']
                start=wait_window(sid)
                if label.startswith('dentry'):
                    args=['dentry','0',str(start),'private' if label.endswith('Private') else 'shared']
                elif label=='unregisteredHolder':args=['fixture','0',str(start),'shared']
                else:args=['file-private' if label.endswith('Private') else 'throughput','3',str(start)]
                running=[launch(label,i,args) for i in range(2)]
                row,report=finish(sid)
                for child in running:assert child.wait(timeout=20)==0
                assert report['quality']['status']=='PASS',report['quality']
                if label=='dentryShared':assert any(e.get('resource')=='lockref' for e in report['findings'])
                if label=='dentryPrivate':assert not report['findings']
                if label=='unregisteredHolder':
                    assert not report['findings']
                    assert any(e['reason']=='unregistered_or_unresolved_owner_identity' for e in report['unknown'])
            summary=dict(prototype_functional_status='PASS',cases=results,plan=plan,
                         source=manifest,performance_certification='NOT_ACCEPTED')
            (out/'result.json').write_text(json.dumps(summary,indent=2))
            print('CIS_PROTOTYPE_RESULT '+json.dumps(summary),flush=True)
            return
        if costs:
            measurements=[]
            for workload in plan['workloads']:
                for repetition in range(plan['pairs']):
                    modes=plan['modes'] if repetition%2==0 else list(reversed(plan['modes']))
                    for mode in modes:
                        label='%s%d%s'%(workload.replace('-',''),repetition,mode)
                        begin=time.monotonic_ns()+500_000_000
                        args=[workload,str(plan['seconds']),str(begin)]
                        if workload=='open-loop':args+=['2000']
                        running=[launch(label,i,args) for i in range(2)]
                        time.sleep(max(0,(begin-time.monotonic_ns())/1e9)+.25)
                        assert all(child.poll() is None for child in running)
                        if mode!='off':
                            sid=request('start',collector=mode,targets=[targets[repetition%2]],nonce=label,window_ms=2000)['session_id']
                            row,report=finish(sid)
                            assert report['quality']['status']=='PASS',report['quality']
                            assert begin<row['window']['start_ns']<row['window']['end_ns']<begin+4_000_000_000
                        for child in running:assert child.wait(timeout=20)==0
                        measurements.append(dict(label=label,mode=mode,repetition=repetition,
                                                 workload=workload,target=repetition%2,start_ns=begin))
            summary=dict(prototype_functional_status='PASS',cases=results,plan=plan,measurements=measurements,
                         source=manifest,performance_certification='NOT_ACCEPTED',
                         scope='fixed 3-pair exploratory costs; whole 4s workload encloses 2s profile, not steady-state certification')
            (out/'result.json').write_text(json.dumps(summary,indent=2))
            print('CIS_PROTOTYPE_RESULT '+json.dumps(summary),flush=True)
            return
        if specialists:
            for label in plan['cases']:
                collector='ip' if label=='quota' else label.split('-')[0]
                for i in range(2):
                    path=root/('root%d'%i)
                    (path/'cpu.max').write_text('20000 100000' if label=='quota' and i==0 else 'max 100000')
                    (path/'memory.high').write_text(str(16<<20) if label=='reclaim-high' and i==0 else 'max')
                    (path/'memory.max').write_text(str(192<<20))
                sid=request('start',collector=collector,targets=targets,nonce=label.replace('-',''),window_ms=2000)['session_id']
                start=wait_window(sid)
                running=[] if label=='sched-idle' else [launch(label,i,
                    ['reclaim' if collector=='reclaim' else 'throughput','3',str(start)],
                    cpu=0 if label=='sched-shared' else i*2) for i in range(2)]
                row,report=finish(sid)
                if label=='reclaim-high':
                    before=time.monotonic_ns()
                    (root/'root0/memory.high').write_text('max')
                    (out/'memory-high-release.json').write_text(json.dumps(dict(
                        before_ns=before,after_ns=time.monotonic_ns(),capture_end_ns=row['window']['end_ns'],
                        value='max',reason='end bounded pressure injection; no change during capture')))
                    assert before>row['window']['end_ns']
                for child in running:assert child.wait(timeout=20)==0
                assert report['quality']['status']=='PASS',report['quality']
                findings=report['findings']
                assert not any(e['kind']=='observed_holder_waiter' for e in findings)
                if label=='sched-shared':assert any(e.get('observation')=='scheduler_wait' for e in findings)
                if label=='reclaim-high':assert any(e.get('observation')=='memcg_reclaim_interval' for e in findings)
                if label in ('sched-idle','reclaim-control'):assert not findings,findings
                if label=='quota':assert any(e['kind']=='cpu_throttling_counter' for e in findings),report
                expected_programs={'ip':1,'sched':1,'reclaim':4}[collector]
                assert len(row['inventory']['programs'])==expected_programs,row['inventory']
                assert (row['inventory']['ip_perf_cpus']>0)==(collector=='ip')
            summary=dict(prototype_functional_status='PASS',cases=results,plan=plan,
                         source=manifest,performance_certification='NOT_ACCEPTED')
            (out/'result.json').write_text(json.dumps(summary,indent=2))
            print('CIS_PROTOTYPE_RESULT '+json.dumps(summary),flush=True)
            return
        for scenario in plan['owner_cases']:
            selected=targets[:1] if scenario=='nonTargetHolder' else targets
            sid=request('start',collector='owner',targets=selected,nonce=scenario,window_ms=2000)['session_id']
            start=wait_window(sid)
            running=[launch(scenario,i,['fixture',str(i if scenario=='private' else 0),str(start),
                          'shared' if scenario=='nonTargetHolder' else scenario],cpu=0 if scenario=='preempt' else i*2) for i in range(2)]
            for child in running:assert child.wait(timeout=20)==0
            row,report=finish(sid)
            assert report['quality']['status']=='PASS',report['quality']
            edges=report['findings']
            if scenario=='private':assert not edges,edges
            else:assert edges,'positive fixture produced no explanation'
            if scenario=='nonTargetHolder':
                a,b=[tuple(map(int,t.split(':'))) for t in targets]
                assert any(tuple(e['waiter'][:2])==a and tuple(e['holder'][:2])==b for e in edges)
            truth=check_owner([json.loads(line) for line in (out/'records'/(sid+'.jsonl')).read_text().splitlines()],
                              [(out/('%s-%d.log'%(scenario,i))).read_text() for i in range(2)])
            (out/(scenario+'-truth.json')).write_text(json.dumps(truth,indent=2))
            assert truth['status']=='PASS',truth

        begin=time.monotonic_ns()+1_000_000_000
        running=[launch('periodic',i,['throughput',str(plan['workload_seconds']),str(begin)]) for i in range(2)]
        for i in range(2):
            deadline=time.monotonic()+.9
            while 'CIS_READY ' not in (out/('periodic-%d.log'%i)).read_text():
                if running[i].poll() is not None or time.monotonic()>deadline:raise RuntimeError('business readiness barrier failed')
                time.sleep(.01)
        time.sleep(max(0,(begin-time.monotonic_ns())/1e9)+.1)
        assert all(child.poll() is None for child in running)
        configured=request('schedule_configure',plan=dict(interval_s=60,jitter_ms=0))
        enabled=request('schedule_enable')
        assert enabled['admission_policy']=='prototype' and enabled['next_ns']>begin
        attempted=set();complete=set();deadline=time.monotonic()+375
        while time.monotonic()<deadline and len(attempted)<6:
            status=request('status')
            if status['state']=='FAULTED':raise RuntimeError(status)
            for sid in status['sessions']:
                if sid in attempted:continue
                small=request('status',session=sid)
                if small.get('scheduled') and small.get('finalized'):
                    row,report=finish(sid);attempted.add(sid)
                    survey=row.get('survey',{}).get('roots',{})
                    if (report['quality']['status']=='PASS' and set(survey)==set(targets) and
                            all(v['valid'] for v in survey.values())):complete.add(sid)
            time.sleep(.5)
        request('schedule_pause');schedule=request('schedule_status')
        assert len(attempted)==6 and len(complete)==6,(attempted,complete,results)
        assert all(row['valid_ns'] is not None for row in schedule['roots'].values())
        assert all(child.poll() is None for child in running),'business exited before sixth sample'
        for child in running:assert child.wait(timeout=30)==0
        for i in range(2):
            text=(out/('periodic-%d.log'%i)).read_text()
            assert 'errors=0' in text and 'CIS_RESULT ' in text
        report=dict(prototype_functional_status='PASS',performance_certification='NOT_ACCEPTED',
                    p1_accepted=False,periodic_slots=len(complete),window_ms=2000,
                    workload_barrier_ns=begin,first_slot_ns=enabled['next_ns'],schedule=schedule,
                    cases=results,source=manifest,limits='two-container functional prototype; no production cost or full-kernel coverage certification')
        (out/'result.json').write_text(json.dumps(report,indent=2))
        print('CIS_PROTOTYPE_RESULT '+json.dumps(report),flush=True)
    finally:
        if daemon.poll() is None:
            request('stop',tolerate=True)
            daemon.wait(timeout=20)
        for child in children:
            if child.poll() is None:child.terminate();child.wait(timeout=10)
        for log in logs:log.close()
        audit.close();controller_log.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--specialists',action='store_true')
    parser.add_argument('--bridge',action='store_true')
    parser.add_argument('--costs',action='store_true')
    args=parser.parse_args()
    if sum((args.specialists,args.bridge,args.costs))>1:parser.error('one frozen protocol per guest')
    run(args.specialists,args.bridge,args.costs)
