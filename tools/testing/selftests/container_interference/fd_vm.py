#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""FD adapter bridge: container-internal threads vs independent tables, n=3."""
import json
import os
from pathlib import Path
import socket
import subprocess
import time
from types import SimpleNamespace

import prototype_admission
from session import source_manifest
from explain import explain, MAX_AUDIT_FINDINGS
from fd_check import check
from fd_population_check import POPULATION_PLAN, check_population
from fd_relation_population import RELATION_PLAN, check_relations
from collector_audit import audit as scope_audit
from source_switches import observe


def run(suite='basic'):
    os.umask(0o077);os.sched_setaffinity(0,{7})
    env=prototype_admission.environment();prototype_admission.check_environment(env)
    out=Path('/tmp/fd-evidence');out.mkdir(mode=0o700)
    root=Path('/sys/fs/cgroup/cis-fd');root.mkdir()
    (root/'management').mkdir();(root/'management/cgroup.procs').write_text(str(os.getpid()))
    (root/'cgroup.subtree_control').write_text('+cpu +memory +cpuset')
    args=SimpleNamespace(worker='/profile/session-worker',residue='/profile/session-residue',bpf='/profile/cis.bpf.o')
    source=source_manifest(args,env['boot_id'])
    permit=prototype_admission.create(source,env,time.monotonic_ns())
    (out/'permit.json').write_text(json.dumps(permit,indent=2))
    if suite not in ('basic','lifecycle'): raise ValueError('unsupported suite')
    plan=dict(schema='cis-fd-plan-v1',cases=['threads','private','native'] if suite=='basic' else ['cross','reuse'],repetitions=3,roots=2,
              window_ms=2000,operations_per_thread=16,fixture_hold_us=100,
              suite=suite,collector='fd',reuse_generations=4,
              population=POPULATION_PLAN,
              relation_population=RELATION_PLAN,
              reuse_allocator='fixture helper allocates on worker CPU then restores management affinity; not a cost test',
              scope='selected FD adapter bridge; full X1 acceptance incomplete',performance_certification='NOT_ACCEPTED')
    (out/'plan.json').write_text(json.dumps(plan,indent=2))
    endpoint='/run/cis-fd.sock';log=(out/'controller.log').open('x')
    daemon=subprocess.Popen(['/usr/bin/python3','/profile/session.py','--socket',endpoint,'--directory',str(out/'records'),
        '--worker',args.worker,'--residue',args.residue,'--bpf',args.bpf,'--admission-policy','prototype',
        '--prototype-permit',str(out/'permit.json'),'daemon'],stdout=log,stderr=log)
    audit=(out/'requests.jsonl').open('x');children=[];handles=[];results=[]

    def request(op,**fields):
        before=time.monotonic_ns();req=dict(version=1,op=op,**fields)
        with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as sock:
            sock.settimeout(15);sock.connect(endpoint);sock.send(json.dumps(req).encode());reply=json.loads(sock.recv(8192))
        audit.write(json.dumps(dict(before_ns=before,after_ns=time.monotonic_ns(),request=req,response=reply))+'\n');audit.flush()
        if not reply['ok']: raise RuntimeError(reply)
        return reply['data']

    def wait_record(sid,field):
        limit=time.monotonic()+20
        while time.monotonic()<limit:
            row=request('status',session=sid)
            if row.get(field): return row
            if row.get('finalized'): raise RuntimeError(row)
            time.sleep(.02 if field=='window' else .1)
        raise TimeoutError(sid)

    def launch(label,index,threads,native,start,local=False):
        handle=(out/('%s-%d.log'%(label,index))).open('x');handles.append(handle)
        child_env=dict(os.environ)
        if local: child_env['CIS_FD_ALLOCATE_LOCAL']='1'
        child=subprocess.Popen(['/session_launch',str(root/('root%d'%index)),str(index*2),'/fd_workload',
             str(threads),str(index*2),str(start),str(native)],stdout=handle,stderr=handle,env=child_env)
        children.append(child);return child

    def launch_cross(label,start):
        handle=(out/(label+'-launcher.log')).open('x');handles.append(handle)
        child=subprocess.Popen(['/fd_cross_workload',str(root/'root0'),str(root/'root1'),
            str(out/(label+'-0.log')),str(out/(label+'-1.log')),str(start)],stdout=handle,stderr=handle)
        children.append(child);return child

    try:
        deadline=time.monotonic()+10
        while not Path(endpoint).exists():
            if daemon.poll() is not None or time.monotonic()>deadline: raise RuntimeError('controller readiness')
            time.sleep(.02)
        targets=[]
        for i in range(2):
            path=root/('root%d'%i);path.mkdir();targets.append(request('register',path=str(path))['target'])
        for native in (0,1):
            start=time.monotonic_ns()+400_000_000
            running=[launch('off%d'%native,i,2,native,start) for i in range(2)]
            for child in running: assert child.wait(timeout=10)==0
        if suite=='lifecycle':
            child=launch_cross('offcross',time.monotonic_ns()+600_000_000)
            assert child.wait(timeout=10)==0
        for repeat in range(3):
            for case in plan['cases']:
                label=case+str(repeat)
                sid=request('start',collector=plan['collector'],targets=targets,nonce=label,window_ms=2000)['session_id']
                window=wait_record(sid,'window')['window']
                active_sources=observe('fd')
                start=max(window['start_ns']+300_000_000,time.monotonic_ns()+100_000_000)
                names=[];boundaries=[]
                for generation in range(4 if case=='reuse' else 1):
                    part=label+'g%d'%generation if case=='reuse' else label
                    start=max(start,time.monotonic_ns()+100_000_000)
                    if case=='cross': start=max(start,time.monotonic_ns()+600_000_000)
                    before=time.monotonic_ns()
                    running=([launch_cross(part,start)] if case=='cross' else
                             [launch(part,i,1 if case=='private' else 2,int(case=='native'),start,local=case=='reuse') for i in range(2)])
                    for child in running: assert child.wait(timeout=10)==0
                    boundaries.append(dict(generation=generation,start_ns=before,end_ns=time.monotonic_ns()))
                    names += [part+'-%d.log'%i for i in range(2)]
                assert time.monotonic_ns()<window['end_ns'],'workload overran measured window'
                row=wait_record(sid,'finalized');assert row['state']=='IDLE' and row.get('objects_absent'),row
                record=json.loads((out/'records'/(sid+'.json')).read_text())
                raw=(out/'records'/(sid+'.jsonl')).read_bytes()
                report=explain(record,raw);scope=scope_audit(record,raw)
                complete_report=explain(record,raw,finding_limit=MAX_AUDIT_FINDINGS)
                truth=check(complete_report,[(out/name).read_text() for name in names],case)
                truth['summary_omitted_findings']=report['omitted_findings']
                truth['audit_finding_limit']=MAX_AUDIT_FINDINGS
                population=check_population([(out/name).read_text() for name in names],raw,window,case,plan['population'])
                relationships=check_relations([(out/name).read_text() for name in names],raw,window,
                                             case,complete_report,plan['relation_population'])
                (out/(label+'-boundaries.json')).write_text(json.dumps(dict(logs=names,groups=boundaries,
                    active_sources=active_sources,idle_sources=observe()),indent=2))
                (out/(label+'-report.json')).write_text(json.dumps(report,indent=2))
                (out/(label+'-truth.json')).write_text(json.dumps(truth,indent=2))
                (out/(label+'-population.json')).write_text(json.dumps(population,indent=2))
                (out/(label+'-relationships.json')).write_text(json.dumps(relationships,indent=2))
                (out/(label+'-scope.json')).write_text(json.dumps(scope,indent=2))
                results.append(dict(label=label,session_id=sid,truth=truth,scope=scope['status']))
                (out/'partial.json').write_text(json.dumps(results,indent=2))
                assert truth['status']=='PASS' and scope['status']=='PASS',(truth,scope)
                assert population['status']=='PASS_SCOPED',population
                assert relationships['status']=='PASS_SCOPED',relationships
        result=dict(status='PASS',source=source,plan=plan,cases=results,
                    unverified=(['full rwsem reader set','dense FD observer cost'] if suite=='lifecycle' else
                                ['explicit CLONE_FILES cross-container bridge','address reuse runtime','full rwsem reader set']),
                    performance_certification='NOT_ACCEPTED')
        (out/'result.json').write_text(json.dumps(result,indent=2));print('CIS_FD_RESULT '+json.dumps(result),flush=True)
    finally:
        for child in children:
            if child.poll() is None: child.terminate()
        for child in children:
            try: child.wait(timeout=5)
            except subprocess.TimeoutExpired: child.kill();child.wait()
        for handle in handles: handle.close()
        if daemon.poll() is None: daemon.terminate()
        try: daemon.wait(timeout=15)
        except subprocess.TimeoutExpired: daemon.kill();daemon.wait()
        audit.close();log.close()


if __name__=='__main__': run(os.environ.get('CIS_FD_SUITE','basic'))
