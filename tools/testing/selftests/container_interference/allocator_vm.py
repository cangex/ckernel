#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
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
from allocator_report import analyze
from allocator_vm_check import check_work
from allocator_fixture_check import CASES, check_case, case_order

ORDER=['off0','allocator0','allocator1','off1','off2','allocator2']


def run(fixture=False,placement=False,failure=False,rollback=False,maple=False,backend_only=False):
    if backend_only and (not fixture or any((placement,failure,rollback,maple))):
        raise ValueError('dedicated selected-backend fixture required')
    collector='alloc_backend' if backend_only else 'allocator'
    if maple and any((fixture,placement,failure,rollback)): raise ValueError('separate Maple cohort')
    if maple:
        from maple_fixture_check import check_work
    else:
        from allocator_vm_check import check_work
    if sum((placement,failure,rollback))>1: raise ValueError('separate cohorts required')
    if placement or failure or rollback: fixture=True
    verify_case=check_case
    if placement:
        from allocator_placement_check import check_case as verify_case, nodes, case_order as placement_order, CASES as placement_cases
    if failure:
        from allocator_failure_check import check_case as verify_case, SETTINGS, case_order as failure_order, CASES as failure_cases
    if rollback:
        from allocator_rollback_check import check_case as verify_case, SETTINGS, case_order as failure_order, CASES as failure_cases
    os.umask(0o077); os.sched_setaffinity(0,{7})
    env=prototype_admission.environment(); prototype_admission.check_environment(env)
    selection = [('alloc_shift','0'),('alloc_cache','cis_alloc_test')] if fixture else [('alloc_shift','6'),('alloc_cache','maple_node')]
    if backend_only: selection=[('alloc_shift','0'),('alloc_cache','maple_node')]
    if maple: selection=[('alloc_shift','0'),('alloc_cache','maple_node')]
    for name,value in selection:
        if Path('/sys/module/cis_observe/parameters/'+name).read_text().strip()!=value:
            raise ValueError('frozen source selection')
    out=Path('/tmp/maple-evidence' if maple else '/tmp/allocator-rollback-evidence' if rollback else '/tmp/allocator-failure-evidence' if failure else '/tmp/allocator-placement-evidence' if placement else '/tmp/allocator-fixture-evidence' if fixture else '/tmp/allocator-evidence'); out.mkdir(mode=0o700)
    root=Path('/sys/fs/cgroup/cis-allocator'); root.mkdir()
    (root/'management').mkdir(); (root/'management/cgroup.procs').write_text(str(os.getpid()))
    (root/'cgroup.subtree_control').write_text('+cpu +memory +cpuset')
    roots=[]
    for i in range(2):
        p=root/('root%d'%i); p.mkdir(); (p/'memory.max').write_text(str(64<<20)); roots.append(p)
    args=SimpleNamespace(worker='/profile/session-worker',residue='/profile/session-residue',bpf='/profile/cis.bpf.o')
    source=source_manifest(args,env['boot_id']); permit=prototype_admission.create(source,env,time.monotonic_ns())
    (out/'permit.json').write_text(json.dumps(permit,indent=2))
    plan=dict(order=ORDER,operations=8,split_regions=128,roots=2,sample_shift=6,cache='maple_node',
              maple_context=True,
              window_ms=2000,cpu=[0,1],management_cpu=7,memory_max_bytes=64<<20,
              scope='ordinary VMA split/merge bridge; no independent allocator-event recall or cost acceptance')
    if maple:
        plan.update(maple_fixture=True,sample_shift=0,operations=8,cycles=2,entries=32,
            scope='private destination trees, native duplication, reinitialization and migrated/RCU release')
    if fixture:
        plan = dict(order=case_order(),cases=list(CASES),rounds=3,operations=4,roots=2,
            sample_shift=0,cache='cis_alloc_test',release_tracking=True,window_ms=2000,cpu=[0,1],free_migration_cpu=[2,3],
            management_cpu=7,memory_max_bytes=64<<20,
            scope='test-only native allocation and release truth; full-rate selected cache, no production recall or free completion claim')
    if backend_only:
        plan.update(collector=collector,boot_cache='maple_node',maple_context=False,
                    backend=dict(cache='cis_alloc_test',nodes=[]))
    if placement:
        topology={str(i):Path('/sys/devices/system/node/node%d/cpulist'%i).read_text().strip() for i in (0,1)}
        if topology!={'0':'0-3','1':'4-7'}: raise ValueError('frozen two-node VM topology')
        plan.update(order=placement_order(),cases=list(placement_cases),operations=8,placement=True,topology=topology,
                    scope='explicit allowed nodes; same cache is not necessarily the same NUMA backend')
    fault_name='fail_page_alloc' if rollback else 'failslab'
    fault_root=Path('/sys/kernel/debug')/fault_name
    def fault_snapshot():
        return dict(settings={name:(fault_root/name).read_text().strip() for name in SETTINGS},
                    caches={} if rollback else {name:Path('/sys/kernel/slab/'+name+'/failslab').read_text().strip()
                            for name in ('cis_alloc_test','cis_alloc_private')})
    if failure or rollback:
        if not Path('/cis-disposable-vm').exists(): raise ValueError('VM-only fault injection')
        original=fault_snapshot()
        (out/(fault_name+'-original.json')).write_text(json.dumps(original,indent=2))
        if original['settings']['probability']!='0' or any(v!='0' for v in original['caches'].values()):
            raise ValueError('unexpected existing fault injection')
        # Only this test cache and explicitly marked tasks can fail.
        for name,value in SETTINGS.items():
            if name!='probability': (fault_root/name).write_text(value)
        if not rollback:
            Path('/sys/kernel/slab/cis_alloc_private/failslab').write_text('0')
            Path('/sys/kernel/slab/cis_alloc_test/failslab').write_text('1')
        else:
            geometry={c:{k:Path('/sys/kernel/slab/'+c+'/'+k).read_text().strip()
                         for k in ('object_size','objs_per_slab')} for c in ('cis_alloc_test','cis_alloc_private')}
            if any(v!={'object_size':'65536','objs_per_slab':'1'} for v in geometry.values()):
                raise ValueError('frozen 4K-page single-object slab geometry')
            if Path('/sys/module/cis_alloc_fixture/parameters/rollback_mode').read_text().strip()!='Y':
                raise ValueError('rollback fixture mode')
            plan.update(rollback=True,geometry=geometry)
        (fault_root/'probability').write_text(SETTINGS['probability'])
        expected_fault=dict(settings=SETTINGS,caches={} if rollback else dict(cis_alloc_test='1',cis_alloc_private='0'))
        if fault_snapshot()!=expected_fault: raise ValueError('failslab configuration readback')
        plan.update(order=failure_order(),cases=list(failure_cases),operations=4 if rollback else 8,failure=failure,
                    fault_configuration=expected_fault,scope='native partial bulk rollback and unmarked recovery' if rollback else 'native failslab pre-hook failure and task/cache negative controls')
    (out/'plan.json').write_text(json.dumps(plan,indent=2))
    endpoint='/run/cis-allocator.sock'; log=(out/'controller.log').open('x')
    daemon=subprocess.Popen(['/usr/bin/python3','/profile/session.py','--socket',endpoint,'--directory',str(out/'records'),
        '--worker',args.worker,'--residue',args.residue,'--bpf',args.bpf,'--admission-policy','prototype',
        '--prototype-permit',str(out/'permit.json'),'daemon'],stdout=log,stderr=log)
    requests=(out/'requests.jsonl').open('x'); children=[]; handles=[]; results=[]

    def request(op,**fields):
        before=time.monotonic_ns(); req=dict(version=1,op=op,**fields)
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
        return dict(time_ns=time.monotonic_ns(),proc_stat=Path('/proc/stat').read_text(),
            memory=Path('/proc/meminfo').read_text(),source_audit=Path('/sys/kernel/debug/cis_alloc_audit').read_text(),
            roots=[{name:(p/name).read_text() for name in ('cpu.stat','memory.current','memory.peak','memory.events')} for p in roots])

    try:
        deadline=time.monotonic()+10
        while not Path(endpoint).exists():
            if daemon.poll() is not None or time.monotonic()>deadline: raise RuntimeError('daemon readiness')
            time.sleep(.02)
        targets=[request('register',path=str(p))['target'] for p in roots]
        for label in plan['order']:
            case = label.split('-')[0] if fixture else None
            collecting = 'allocator' in label
            placement_before=None
            if placement:
                for i,p in enumerate(roots):
                    (p/'cpuset.cpus').write_text(str(i))
                    (p/'cpuset.mems').write_text(str(nodes(case)[i]))
                placement_before=[dict(cpu=(p/'cpuset.cpus.effective').read_text().strip(),
                    mems=(p/'cpuset.mems.effective').read_text().strip()) for p in roots]
            fault_before=fault_snapshot() if failure or rollback else None
            sid=None; source_before=snapshot()
            if collecting:
                selected=dict(backend=plan['backend']) if backend_only else {}
                sid=request('start',collector=collector,targets=targets,nonce=label.replace('-',''),window_ms=2000,**selected)['session_id']
                window=wait(sid,'window')['window']; active=observe(collector)
            else:
                now=time.monotonic_ns(); window=dict(start_ns=now,end_ns=now+2_000_000_000); active=observe(None)
            start=max(window['start_ns']+300_000_000,time.monotonic_ns()+100_000_000)
            before=snapshot(); running=[]
            for i,p in enumerate(roots):
                handle=(out/(label+'-%d.log'%i)).open('x'); handles.append(handle)
                command = ['/allocator_fixture_workload',case,str(start),str(int(case=='private' and i==1)),str(i)] if fixture else ['/allocator_workload',str(start)]
                if placement: command=['/allocator_placement_workload',str(start),str(nodes(case)[i])]
                if failure: command=['/allocator_failure_workload',case,str(start),str(i)]
                if rollback: command=['/allocator_rollback_workload',case,str(start),str(i)]
                if maple: command=['/maple_workload',str(start),str(i)]
                child=subprocess.Popen(['/session_launch',str(p),str(i),*command],stdout=handle,stderr=handle)
                children.append(child); running.append(child)
            codes=[p.wait(timeout=10) for p in running]; after=snapshot()
            if codes!=[0,0] or after['time_ns']>=window['end_ns']: raise ValueError('workload completion/window')
            logs=[(out/(label+'-%d.log'%i)).read_text() for i in range(2)]
            if sid:
                row=wait(sid,'finalized'); idle=observe(None)
                record=json.loads((out/'records'/(sid+'.json')).read_text())
                report=analyze(record,(out/'records'/(sid+'.jsonl')).read_bytes())
                identities = [record['root_identities'][t] for t in targets]
                result=verify_case(case,window,logs,report,identities,require_releases=True) if fixture else check_work(window,logs,report,identities,**({} if maple else {'require_maple':True}))
                (out/(label+'-report.json')).write_text(json.dumps(report,indent=2))
                if not row.get('objects_absent'): raise ValueError('capture cleanup')
            else:
                idle=observe(None)
                result=verify_case(case,window,logs,require_releases=True) if fixture else check_work(window,logs)
            evidence=dict(label=label,session_id=sid,window=window,active_sources=active,idle_sources=idle,
                targets=targets,before=before,after=after,source_before=source_before,source_after=snapshot(),exit_codes=codes,result=result)
            if placement:
                evidence['placement_before']=placement_before
                evidence['placement_after']=[dict(cpu=(p/'cpuset.cpus.effective').read_text().strip(),
                    mems=(p/'cpuset.mems.effective').read_text().strip()) for p in roots]
            if failure or rollback:
                evidence['fault_before']=fault_before
                evidence['fault_after']=fault_snapshot()
                if fault_before!=expected_fault or evidence['fault_after']!=expected_fault:
                    raise ValueError('fault settings changed')
            (out/(label+'-evidence.json')).write_text(json.dumps(evidence,indent=2)); results.append(evidence)
            if result['status']!='PASS': raise ValueError(result)
        (out/'result.json').write_text(json.dumps(dict(status='PASS',source=source,plan=plan,states=results),indent=2))
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
        if failure or rollback:
            (fault_root/'probability').write_text('0')
            for name,value in original['caches'].items(): Path('/sys/kernel/slab/'+name+'/failslab').write_text(value)
            for name,value in original['settings'].items():
                if name!='probability': (fault_root/name).write_text(value)
            (fault_root/'probability').write_text(original['settings']['probability'])
            restored=fault_snapshot()
            (out/(fault_name+'-restored.json')).write_text(json.dumps(restored,indent=2))
            if restored!=original: raise ValueError('failslab restore')


if __name__=='__main__': run()
