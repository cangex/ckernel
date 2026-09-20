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
from queue_report import analyze
from y5_queue_check import CASES,order,check


def run(guard=False):
    os.umask(0o077); os.sched_setaffinity(0,{7})
    env=admission.environment(); admission.check_environment(env)
    if not Path('/cis-disposable-vm').exists(): raise PermissionError('disposable VM only')
    out=Path('/tmp/y5-queue-guard' if guard else '/tmp/y5-queue-evidence'); out.mkdir(mode=0o700)
    from y5_queue_guard import order as guard_order,check as guard_check
    run_order=guard_order() if guard else order()
    commands=[]; namespaces=[]; interfaces=[]; handles=[]; children=[]; netfds=[]; daemon=None
    endpoint='/run/cis-y5-queue.sock'
    requests=(out/'requests.jsonl').open('x'); log=(out/'controller.log').open('x')

    def command(*args):
        r=subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        commands.append(dict(command=args,returncode=r.returncode,stdout=r.stdout,stderr=r.stderr,time_ns=time.monotonic_ns()))
        (out/'commands.json').write_text(json.dumps(commands,indent=2))
        if r.returncode: raise RuntimeError(commands[-1])
        return r.stdout

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
            native=Path('/sys/kernel/debug/cis_queue_audit').read_text(),
            queues=[json.loads(command('/usr/sbin/tc','-s','-j','qdisc','show','dev','cisy5ex%d'%i)) for i in range(2)],
            roots=[{n:(p/n).read_text() for n in ('cpu.stat','memory.current','memory.peak','memory.events')} for p in roots],
            after_ns=time.monotonic_ns())

    try:
        Path('/proc/sys/net/ipv4/ip_forward').write_text('1')
        for i in range(2):
            for kind,prefix,subnet in (('s','ex','172.%d.0'%(30+i)),('a','in','10.42.%d'%i)):
                ns='cisy5%s%d'%(kind,i); dev='cisy5%s%d'%(prefix,i); peer='cisy5p%s%d'%(kind,i)
                command('/usr/sbin/ip','netns','add',ns); namespaces.append(ns)
                command('/usr/sbin/ip','link','add',dev,'type','veth','peer','name',peer); interfaces.append(dev)
                command('/usr/sbin/ip','link','set',peer,'netns',ns)
                command('/usr/sbin/ip','addr','add',subnet+'.1/24','dev',dev)
                command('/usr/sbin/ip','link','set',dev,'up')
                command('/usr/sbin/ip','-n',ns,'link','set','lo','up')
                command('/usr/sbin/ip','-n',ns,'addr','add',subnet+'.2/24','dev',peer)
                command('/usr/sbin/ip','-n',ns,'link','set',peer,'up')
                command('/usr/sbin/ip','-n',ns,'route','add','default','via',subnet+'.1')
        hostnet=os.open('/proc/self/ns/net',os.O_RDONLY|os.O_CLOEXEC); netfds.append(hostnet)
        sinkfds=[os.open('/run/netns/cisy5s%d'%i,os.O_RDONLY|os.O_CLOEXEC) for i in range(2)]; netfds+=sinkfds
        actorfds=[os.open('/run/netns/cisy5a%d'%i,os.O_RDONLY|os.O_CLOEXEC) for i in range(2)]; netfds+=actorfds
        selected=int(Path('/sys/class/net/cisy5ex0/ifindex').read_text())
        root=Path('/sys/fs/cgroup/cis-y5-queue'); root.mkdir(); (root/'management').mkdir()
        (root/'management/cgroup.procs').write_text(str(os.getpid()))
        (root/'cgroup.subtree_control').write_text('+cpu +memory +cpuset')
        for i in range(2):
            p=root/('root%d'%i); p.mkdir(); (p/'memory.max').write_text(str(64<<20)); roots.append(p)
        args=SimpleNamespace(worker='/profile/session-worker',residue='/profile/session-residue',bpf='/profile/cis.bpf.o')
        source=source_manifest(args,env['boot_id']); permit=admission.create(source,env,time.monotonic_ns())
        (out/'permit.json').write_text(json.dumps(permit,indent=2))
        plan=dict(schema='cis-y5-queue-guard-v1' if guard else 'cis-y5-queue-plan-v1',order=run_order,cases=CASES,source=source,window_ms=2000,
            selected_ifindex=selected,tx_queue=0,udp_datagrams_per_actor=1000,payload_bytes=1024,
            rate_per_actor=1000,egress_rate='2mbit',egress_limit_bytes=65536,cpu=[0,1],management_cpu=7,
            direct_scope='containers use shared host network namespace, private UDP sockets created after cgroup entry',
            forwarded_scope='separate container network namespaces via host forwarding, source owner deliberately unknown')
        (out/'plan.json').write_text(json.dumps(plan,indent=2))
        daemon=subprocess.Popen(['/usr/bin/python3','/profile/session.py','--socket',endpoint,'--directory',str(out/'records'),
            '--worker',args.worker,'--residue',args.residue,'--bpf',args.bpf,'--admission-policy','prototype',
            '--prototype-permit',str(out/'permit.json'),'daemon'],stdout=log,stderr=log)
        deadline=time.monotonic()+10
        while not Path(endpoint).exists():
            if daemon.poll() is not None or time.monotonic()>deadline: raise RuntimeError('readiness')
            time.sleep(.02)
        targets=[request('register',path=str(p))['target'] for p in roots]; states=[]
        for entry in run_order:
            label=entry['label']; case=entry['case']; c=CASES['sharedDirect'] if guard else CASES[case]; sid=None
            for i in range(2):
                command('/usr/sbin/tc','qdisc','replace','dev','cisy5ex%d'%i,'root','handle','1:',
                        'tbf','rate','2mbit','burst','8192','limit','65536')
            before=snapshot()
            if entry['enabled']:
                sid=request('start',collector='qdisc',queue=dict(ifindex=selected,tx_queue=0),
                            targets=targets,nonce=label,window_ms=2000)['session_id']
                window=wait(sid,'window')['window']; active=observe('qdisc')
            else:
                t=time.monotonic_ns(); window=dict(start_ns=t,end_ns=t+2_000_000_000); active=observe(None)
            sinks=[]
            for i,fd in enumerate(sinkfds):
                path=out/(label+'-sink%d.json'%i); h=(out/(label+'-sink%d.log'%i)).open('x'); handles.append(h)
                p=subprocess.Popen(['/usr/bin/python3','/profile/queue_sink.py',str(fd),str(path),str(window['end_ns']+(3_000_000_000 if guard else 250_000_000))],
                    pass_fds=(fd,),stdout=h,stderr=h); children.append(p); sinks.append(p)
            deadline=time.monotonic()+3
            while not all((out/(label+'-sink%d.ready'%i)).exists() for i in range(2)):
                if any(p.poll() is not None for p in sinks) or time.monotonic()>deadline: raise RuntimeError('sink readiness')
                time.sleep(.01)
            start=max(window['start_ns']+400_000_000,time.monotonic_ns()+100_000_000); running=[]
            for i,p in enumerate(roots):
                fd=actorfds[i] if c['forwarded'] else hostnet; h=(out/(label+'-%d.log'%i)).open('x'); handles.append(h)
                child=subprocess.Popen(['/session_launch',str(p),str(i),'/queue_workload',str(fd),str(i),
                    '172.%d.0.2'%(30+c['destinations'][i]),str(start)]+(['storm'] if guard else []),pass_fds=(fd,),stdout=h,stderr=h)
                children.append(child); running.append(child)
            detached=None
            if guard:
                if sid: wait(sid,'finalized')
                else: time.sleep(max(0,(window['end_ns']-time.monotonic_ns())/1e9))
                idle=observe(None); detached=snapshot()
            codes=[p.wait(timeout=10) for p in running]
            if any(p.wait(timeout=10) for p in sinks): raise RuntimeError('sink exit')
            report=None; identities=None
            if sid:
                wait(sid,'finalized'); record=json.loads((out/'records'/(sid+'.json')).read_text())
                report=analyze(record,(out/'records'/(sid+'.jsonl')).read_bytes())
                identities=[record['root_identities'][t] for t in targets]
                (out/(label+'-report.json')).write_text(json.dumps(report,indent=2))
            idle=observe(None); after=snapshot()
            evidence=dict(**entry,session_id=sid,targets=targets,window=window,before=before,after=after,
                active_sources=active,idle_sources=idle,exit_codes=codes,detached=detached)
            logs=[(out/(label+'-%d.log'%i)).read_text() for i in range(2)]
            checked=(guard_check(record if sid else None,(out/'records'/(sid+'.jsonl')).read_bytes() if sid else None,logs,evidence)
                if guard else check(case,window,logs,[json.loads((out/(label+'-sink%d.json'%i)).read_text()) for i in range(2)],report,identities))
            evidence['result']=checked
            states.append(evidence); (out/(label+'-evidence.json')).write_text(json.dumps(evidence,indent=2))
            (out/'partial.json').write_text(json.dumps(states,indent=2))
            if checked['status']!=('PASS_PROTECTION_ONLY' if guard else 'PASS_SCOPED') or codes!=[0,0]: raise ValueError(checked)
        (out/'result.json').write_text(json.dumps(dict(status='PASS_PROTECTION_ONLY' if guard else 'PASS_SCOPED',source=source,states=states),indent=2))
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
        for fd in netfds: os.close(fd)
        for h in handles: h.close()
        requests.close(); log.close()
        # Our lease is gone before destroying the devices it pins.
        for dev in reversed(interfaces): command('/usr/sbin/ip','link','del',dev)
        for ns in reversed(namespaces): command('/usr/sbin/ip','netns','del',ns)


if __name__=='__main__': run(guard=os.environ.get('CIS_QUEUE_GUARD')=='1')
