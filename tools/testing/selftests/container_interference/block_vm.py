#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import time
from types import SimpleNamespace

import prototype_admission
from session import source_manifest
from source_switches import observe
from block_report import analyze
from block_fixture_check import case_order,check_case,check_counters,COUNTERS,FIXTURES
import block_merge_check


def run(fixture=None):
    if fixture is not None and fixture not in FIXTURES: raise ValueError('fixture mode')
    os.umask(0o077); os.sched_setaffinity(0,{7})
    if not Path('/cis-disposable-vm').exists(): raise PermissionError('disposable VM only')
    env=prototype_admission.environment(); prototype_admission.check_environment(env)
    out=Path('/tmp/block-evidence'); out.mkdir(mode=0o700)
    root=Path('/sys/fs/cgroup/cis-block'); root.mkdir(); (root/'management').mkdir()
    (root/'management/cgroup.procs').write_text(str(os.getpid()))
    (root/'cgroup.subtree_control').write_text('+cpu +memory +cpuset +io')
    roots=[]
    for i in range(2):
        p=root/('root%d'%i); p.mkdir(); (p/'memory.max').write_text(str(64<<20)); roots.append(p)
    args=SimpleNamespace(worker='/profile/session-worker',residue='/profile/session-residue',bpf='/profile/cis.bpf.o')
    source=source_manifest(args,env['boot_id']); permit=prototype_admission.create(source,env,time.monotonic_ns())
    (out/'permit.json').write_text(json.dumps(permit,indent=2))
    plan=dict(order=case_order(),rounds=3,operations_per_actor=8,window_ms=2000,cpu=[0,1],management_cpu=7,
        devices=['/dev/vda','/dev/vdb'],device_bytes=16<<20,direct=True,bytes_per_io=4096,verify_head_bio_blkcg=True,
        scope='two disposable virtual disks, independent offsets; shared device is not a proven blocker')
    if fixture:
        plan.update(fixture=fixture,devices=['/dev/cisblock0','/dev/cisblock1'],
            scope='disposable memory device request lifecycle; not production device contention')
        selected=int(Path('/sys/module/cis_block_fixture/parameters/test_mode').read_text())
        if selected!=FIXTURES.index(fixture)+1: raise ValueError('fixture module configuration')
    if fixture=='merge':
        plan.update(order=block_merge_check.case_order(),direct=False,operations_per_actor=None,
                    mechanism='native submit_bio with plug; independent driver request truth',cases=block_merge_check.CASES)
    (out/'plan.json').write_text(json.dumps(plan,indent=2))
    fds=[]
    for path in plan['devices']:
        fd=os.open(path,os.O_RDWR|os.O_DIRECT); fds.append(fd)
        if not stat.S_ISBLK(os.fstat(fd).st_mode) or os.lseek(fd,0,os.SEEK_END)!=plan['device_bytes']:
            raise ValueError('unexpected disposable device')
    endpoint='/run/cis-block.sock'; log=(out/'controller.log').open('x')
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
        result=dict(time_ns=time.monotonic_ns(),proc_stat=Path('/proc/stat').read_text(),memory=Path('/proc/meminfo').read_text(),
            roots=[{name:(p/name).read_text() for name in ('cpu.stat','memory.current','memory.peak','memory.events')} for p in roots])
        if fixture:
            result['fixture_counters']={k:int((Path('/sys/module/cis_block_fixture/parameters')/k).read_text()) for k in COUNTERS}
        return result

    try:
        deadline=time.monotonic()+10
        while not Path(endpoint).exists():
            if daemon.poll() is not None or time.monotonic()>deadline: raise RuntimeError('daemon readiness')
            time.sleep(.02)
        targets=[request('register',path=str(p))['target'] for p in roots]
        for label in plan['order']:
            case=label.split('-')[0]; collecting='-block' in label; sid=None
            selected=[fds[0],fds[0] if case=='shared' or fixture=='merge' else fds[1]]
            if collecting:
                sid=request('start',collector='block',targets=targets,nonce=label.replace('-',''),window_ms=2000)['session_id']
                window=wait(sid,'window')['window']; active=observe('block')
            else:
                now=time.monotonic_ns(); window=dict(start_ns=now,end_ns=now+2_000_000_000); active=observe(None)
            start=max(window['start_ns']+300_000_000,time.monotonic_ns()+100_000_000)
            before=snapshot(); running=[]
            for i,p in enumerate(roots):
                handle=(out/(label+'-%d.log'%i)).open('x'); handles.append(handle); fd=selected[i]
                command=['/session_launch',str(p),str(i),'/block_workload',str(fd),str(i),str(start)]
                if fixture=='merge':
                    command[3]='/block_merge_workload'
                    command += [str(v) for v in block_merge_check.CASES[case]]
                child=subprocess.Popen(command,
                    stdout=handle,stderr=handle,pass_fds=(fd,))
                children.append(child); running.append(child)
            codes=[p.wait(timeout=10) for p in running]; after=snapshot()
            if codes!=[0,0] or after['time_ns']>=window['end_ns']: raise ValueError(('workload completion/window',codes))
            logs=[(out/(label+'-%d.log'%i)).read_text() for i in range(2)]; report=None; identities=None
            if sid:
                row=wait(sid,'finalized'); idle=observe(None)
                record=json.loads((out/'records'/(sid+'.json')).read_text())
                report=analyze(record,(out/'records'/(sid+'.jsonl')).read_bytes())
                identities=[record['root_identities'][t] for t in targets]
                (out/(label+'-report.json')).write_text(json.dumps(report,indent=2))
                if not row.get('objects_absent'): raise ValueError('capture cleanup')
            else: idle=observe(None)
            result=(block_merge_check.check_case(case,window,logs,report,identities) if fixture=='merge' else
                    check_case(case,window,logs,report,identities,verify_blkcg=True,fixture=fixture))
            if fixture=='merge':
                result['fixture_counters']=block_merge_check.check_counters(before['fixture_counters'],after['fixture_counters'],result)
                if result['fixture_counters']['status']!='PASS': result['status']='FAIL'
            elif fixture:
                result['fixture_counters']=check_counters(fixture,before['fixture_counters'],after['fixture_counters'])
                if result['fixture_counters']['status']!='PASS': result['status']='FAIL'
            evidence=dict(label=label,session_id=sid,window=window,active_sources=active,idle_sources=idle,
                targets=targets,before=before,after=after,exit_codes=codes,result=result)
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


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(); parser.add_argument('--fixture',choices=FIXTURES)
    run(parser.parse_args().fixture)
