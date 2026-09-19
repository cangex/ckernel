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
from net_report import analyze
from net_fixture_check import CASES,RIGHTS_CASES,ORIGIN_CASES,case_order,check_case
from net_source_audit import delta


def tcp_pair():
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as listener:
        listener.settimeout(3); listener.bind(('127.0.0.1',0)); listener.listen(1)
        client=socket.socket(socket.AF_INET,socket.SOCK_STREAM); client.settimeout(3)
        try:
            client.connect(listener.getsockname()); server,_=listener.accept()
            server.settimeout(3)
            for sock in (client,server): sock.getsockopt(socket.SOL_SOCKET,57,8)
            return client,server
        except BaseException: client.close(); raise


def run(backlog=False,rights=False,origin=False,capacity=False,txfailure=False,txadmission=False):
    os.umask(0o077); os.sched_setaffinity(0,{7})
    env=prototype_admission.environment(); prototype_admission.check_environment(env)
    if Path('/sys/module/cis_observe/parameters/net_shift').read_text().strip()!='0':
        raise ValueError('full-rate native cookie fixture selection required')
    out=Path('/tmp/net-evidence'); out.mkdir(mode=0o700)
    fault=None; admission=None
    if txfailure:
        from net_tx_fault import NativeTxFault
        fault=NativeTxFault(out)
    if txadmission:
        from net_tx_admission import NativeTxAdmission
        admission=NativeTxAdmission(out,tcp_pair)
    root=Path('/sys/fs/cgroup/cis-net'); root.mkdir(); (root/'management').mkdir()
    (root/'management/cgroup.procs').write_text(str(os.getpid()))
    (root/'cgroup.subtree_control').write_text('+cpu +memory +cpuset')
    roots=[]
    for i in range(2):
        p=root/('root%d'%i); p.mkdir(); (p/'memory.max').write_text(str(64<<20)); roots.append(p)
    args=SimpleNamespace(worker='/profile/session-worker',residue='/profile/session-residue',bpf='/profile/cis.bpf.o')
    source=source_manifest(args,env['boot_id']); permit=prototype_admission.create(source,env,time.monotonic_ns())
    (out/'permit.json').write_text(json.dumps(permit,indent=2))
    rights=rights or origin
    cases=('capacity',) if capacity else ORIGIN_CASES if origin else ('backlog',) if backlog else RIGHTS_CASES if rights else CASES
    if txfailure:
        from net_tx_failure_check import CASES as failure_cases
        cases=failure_cases
    if txadmission:
        from net_tx_admission_check import CASES as admission_cases
        cases=admission_cases
    plan=dict(order=case_order(cases),cases=list(cases),rounds=3,operations=4,roots=2,net_shift=0,
        window_ms=2000,cpu=[0,1],management_cpu=7,memory_max_bytes=64<<20,
        hold_ms=30,waiter_offset_ms=5,socket_namespace='inherited VM loopback TCP socket; tasks in separate container namespaces',
        scope='logical lock fixture with deliberate bounded sleep while held, not ordinary application cost acceptance')
    (out/'plan.json').write_text(json.dumps(plan,indent=2))
    if txfailure:
        plan.update(operations=8,send_bytes=128,operation_spacing_ms=100,tx_failure_validation=True,
                    scope='native task/cache-filtered failslab, same-socket unmarked recovery and private normal actor',
                    socket_namespace='inherited distinct VM loopback TCP pairs; no shared socket')
        (out/'plan.json').write_text(json.dumps(plan,indent=2))
    if txadmission:
        plan.update(operations=24,send_bytes=128,pressure_operations=16,recovery_operations=8,
                    operation_spacing_ms=10,tx_admission_validation=True,seed_bytes=4<<20,
                    scope='native TCP_REPAIR queue acceptance under VM-only budget; no wire delivery or performance claim')
        (out/'plan.json').write_text(json.dumps(plan,indent=2))
    if capacity:
        plan.update(capacity_per_actor=40,watch_capacity=64,post_detach_operations=40,
                    scope='native Socket watch overflow must reject attribution, then resume same actors')
        (out/'plan.json').write_text(json.dumps(plan,indent=2))
    if backlog:
        plan.update(unheld_drain_transfers=1,drain_offset_ms=450,skb_release_not_bounded_by_recv_return=True,
                    tx_allocation_validation=True)
        (out/'plan.json').write_text(json.dumps(plan,indent=2))
    if rights:
        plan.update(socket_namespace='TCP socket created inside actor0 network namespace; passed with SCM_RIGHTS',
            fd_transfer='real SCM_RIGHTS; rightsPrivate recipient creates a different TCP socket',
            creator_attribution='fixture truth only; observer creation owner remains UNOBSERVED')
        (out/'plan.json').write_text(json.dumps(plan,indent=2))
    if origin:
        plan.update(origin_validation=True,creator_attribution='native post-create task distinct from acceptor and transferred user',
            origin_case='rightsAccept transfers a passive accepted child, not the listening socket',
            origin_prepare_before_lock_ms=300,lock_start_after_window_ms=500,
            excluded_protocols=['raw_tcp','udp'])
        (out/'plan.json').write_text(json.dumps(plan,indent=2))
    endpoint='/run/cis-net.sock'; log=(out/'controller.log').open('x')
    daemon=subprocess.Popen(['/usr/bin/python3','/profile/session.py','--socket',endpoint,'--directory',str(out/'records'),
        '--worker',args.worker,'--residue',args.residue,'--bpf',args.bpf,'--admission-policy','prototype',
        '--prototype-permit',str(out/'permit.json'),'daemon'],stdout=log,stderr=log)
    requests=(out/'requests.jsonl').open('x'); children=[]; handles=[]; sockets=[]; results=[]

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
            memory=Path('/proc/meminfo').read_text(),source_audit=Path('/sys/kernel/debug/cis_net_audit').read_text(),
            roots=[{name:(p/name).read_text() for name in ('cpu.stat','memory.current','memory.peak','memory.events')} for p in roots])

    try:
        if fault: fault.enable()
        if admission: admission.prepare()
        deadline=time.monotonic()+10
        while not Path(endpoint).exists():
            if daemon.poll() is not None or time.monotonic()>deadline: raise RuntimeError('daemon readiness')
            time.sleep(.02)
        targets=[request('register',path=str(p))['target'] for p in roots]
        for label in plan['order']:
            case=label.split('-')[0]; collecting='-net' in label; sid=None
            client,server=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET) if rights else tcp_pair()
            sockets.extend((client,server)); selected=[client,server] if rights else [server,server]
            peers=[]
            if txfailure or txadmission:
                other_client,other_server=tcp_pair(); sockets.extend((other_client,other_server))
                selected=[server,other_server]; peers=[client,other_client]
            if case=='backlog': selected=[server,client]
            if case=='private':
                other_client,other_server=tcp_pair(); sockets.extend((other_client,other_server)); selected[1]=other_server
            channels=[]
            child_channels=[]
            if capacity:
                for i in range(2):
                    parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
                    parent.settimeout(10); sockets.extend((parent,child)); channels.append(parent); selected[i]=child
            if txadmission:
                from net_tx_admission import repair
                for sock in selected: repair(sock,4<<20)
                for i in range(2):
                    parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
                    parent.settimeout(5); sockets.extend((parent,child)); channels.append(parent); child_channels.append(child)
                limited=admission.limit(case=='txadmission')
            source_before=snapshot()
            if collecting:
                sid=request('start',collector='net',targets=targets,nonce=label.replace('-',''),window_ms=2000)['session_id']
                window=wait(sid,'window')['window']; active=observe('net')
            else:
                now=time.monotonic_ns(); window=dict(start_ns=now,end_ns=now+2_000_000_000); active=observe(None)
            start=(max(window['start_ns']+500_000_000,time.monotonic_ns()+400_000_000) if origin else
                   max(window['start_ns']+300_000_000,time.monotonic_ns()+100_000_000))
            before=snapshot(); running=[]
            for i,p in enumerate(roots):
                handle=(out/(label+'-%d.log'%i)).open('x'); handles.append(handle)
                fd=selected[i].fileno()
                workload='/net_capacity_workload' if capacity else '/net_backlog_workload' if case=='backlog' else '/net_workload'
                extra=[]; passed=(fd,)
                if txfailure:
                    workload='/net_tx_failure_workload'; extra=[str(peers[i].fileno())]; passed=(fd,peers[i].fileno())
                if txadmission:
                    workload='/net_tx_admission_workload'; extra=[str(child_channels[i].fileno())]; passed=(fd,child_channels[i].fileno())
                child=subprocess.Popen(['/session_launch',str(p),str(i),workload,str(fd),str(i),str(start),case]
                    +(['origin'] if origin else [])+extra,stdout=handle,stderr=handle,pass_fds=passed)
                children.append(child); running.append(child)
            if txfailure:
                for sock in sockets: sock.close()
                sockets.clear()
            if txadmission:
                for sock in selected+child_channels: sock.close()
                for channel in channels:
                    if channel.recv(1)!=b'R': raise ValueError('admission pressure completion barrier')
                restored=admission.limit(False)
                for channel in channels: channel.sendall(b'D')
            if capacity:
                for channel in channels:
                    if channel.recv(1)!=b'R': raise ValueError('capacity fixture readiness')
                if sid: wait(sid,'finalized')
                capacity_idle=observe(None)
                post_detach_source=snapshot()
                for channel in channels: channel.sendall(b'D')
            codes=[p.wait(timeout=10) for p in running]; after=snapshot()
            if codes!=[0,0] or not capacity and after['time_ns']>=window['end_ns']: raise ValueError(('workload completion/window',codes))
            logs=[(out/(label+'-%d.log'%i)).read_text() for i in range(2)]; report=None; identities=None
            if sid:
                row=wait(sid,'finalized'); idle=observe(None)
                record=json.loads((out/'records'/(sid+'.json')).read_text())
                report=analyze(record,(out/'records'/(sid+'.jsonl')).read_bytes())
                identities=[record['root_identities'][t] for t in targets]
                (out/(label+'-report.json')).write_text(json.dumps(report,indent=2))
                if not row.get('objects_absent'): raise ValueError('capture cleanup')
            else: idle=observe(None)
            if txadmission:
                from net_tx_admission_check import check as check_tx_admission
                result=check_tx_admission(case,window,logs,limited,restored,report,identities)
            elif txfailure:
                from net_tx_failure_check import check as check_tx_failure
                result=check_tx_failure(case,window,logs,report,identities)
            elif capacity:
                from net_capacity_check import check as check_capacity
                idle=capacity_idle
                result=check_capacity(window,logs,record if sid else None,
                    (out/'records'/(sid+'.jsonl')).read_bytes() if sid else None,idle)
            else:
                result=check_case(case,window,logs,report,identities,require_origin=origin,require_protocol_negative=origin,
                                  require_tx=backlog)
            evidence=dict(label=label,session_id=sid,window=window,active_sources=active,idle_sources=idle,
                targets=targets,before=before,after=after,source_before=source_before,source_after=snapshot(),exit_codes=codes,result=result)
            evidence['source_delta']=delta(evidence['source_before'],evidence['source_after'])
            if txadmission:
                evidence.update(memory_configuration=limited,memory_restored=restored)
            if capacity:
                evidence['post_detach_source_before']=post_detach_source
                evidence['post_detach_source_delta']=delta(post_detach_source,evidence['source_after'])
                if any(evidence['post_detach_source_delta']['totals'].values()):
                    raise ValueError('network callbacks continued after detach')
            (out/(label+'-evidence.json')).write_text(json.dumps(evidence,indent=2)); results.append(evidence)
            for sock in sockets: sock.close()
            sockets.clear()
            if result['status']!='PASS': raise ValueError(result)
        (out/'result.json').write_text(json.dumps(dict(status='PASS',source=source,plan=plan,states=results),indent=2))
    finally:
        for p in children:
            if p.poll() is None: p.terminate()
        for p in children:
            try: p.wait(timeout=5)
            except subprocess.TimeoutExpired: p.kill(); p.wait()
        for sock in sockets: sock.close()
        for h in handles: h.close()
        if daemon.poll() is None: daemon.terminate()
        try: daemon.wait(timeout=15)
        except subprocess.TimeoutExpired: daemon.kill(); daemon.wait()
        requests.close(); log.close()
        if fault: fault.restore()
        if admission: admission.restore()


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(); group=parser.add_mutually_exclusive_group()
    group.add_argument('--backlog',action='store_true'); group.add_argument('--rights',action='store_true')
    group.add_argument('--origin',action='store_true')
    group.add_argument('--capacity',action='store_true')
    group.add_argument('--txfailure',action='store_true')
    group.add_argument('--txadmission',action='store_true')
    a=parser.parse_args(); run(a.backlog,a.rights,a.origin,a.capacity,a.txfailure,a.txadmission)
