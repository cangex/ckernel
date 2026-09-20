#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
import json
import os
from pathlib import Path
import resource
import socket
import subprocess
import time
from types import SimpleNamespace
import prototype_admission as admission
from joint_costs import snapshot
from session import source_manifest
from source_switches import observe
from y7_private_check import order, ROLES, cost_fields
from y7_queue_check import captures, check, validate_plan

def run():
    os.umask(0o077);os.sched_setaffinity(0,{7})
    env=admission.environment();admission.check_environment(env)
    arrangement=Path('/y7-arrangement').read_text().strip()
    if not Path('/cis-disposable-vm').exists() or arrangement not in ('shared','separate'):
        raise PermissionError('disposable cohort required')
    out=Path('/tmp/y7-queue-evidence');out.mkdir(mode=0o700)
    endpoint='/run/cis-y7.sock';children=[];handles=[];fds=[];daemon=None;interfaces=[];namespaces=[];commands=[]
    requests=(out/'requests.jsonl').open('x');log=(out/'controller.log').open('x')
    def command(*args):
        p=subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        commands.append(dict(command=args,returncode=p.returncode,stdout=p.stdout,stderr=p.stderr,time_ns=time.monotonic_ns()))
        (out/'commands.json').write_text(json.dumps(commands,indent=2))
        if p.returncode: raise RuntimeError(commands[-1])
        return p.stdout
    def request(op,**kw):
        req=dict(version=1,op=op,**kw);begin=time.monotonic_ns()
        with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as sock:
            sock.settimeout(15);sock.connect(endpoint);sock.send(json.dumps(req).encode());reply=json.loads(sock.recv(16384))
        kept=reply
        if op=='status' and reply.get('ok'):
            kept=dict(reply,data={k:reply['data'][k] for k in ('state','session_id','finalized') if k in reply['data']})
        requests.write(json.dumps(dict(before_ns=begin,after_ns=time.monotonic_ns(),request=req,response=kept))+'\n');requests.flush()
        if not reply['ok']: raise RuntimeError(reply)
        return reply['data']
    def wait(sid,field):
        deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            row=request('status',session=sid)
            if row.get(field): return row
            if row.get('finalized'): raise RuntimeError(row)
            time.sleep(.05)
        raise TimeoutError(sid)
    def snap():
        v=snapshot(root,roots)
        v['queue_audit']=Path('/sys/kernel/debug/cis_queue_audit').read_text()
        v['queues']=[json.loads(command('/usr/sbin/tc','-s','-j','qdisc','show','dev','cisy7ex%d'%i)) for i in range(2)]
        return v
    try:
        for i in range(2):
            ns='cisy7s%d'%i;dev='cisy7ex%d'%i;peer='cisy7p%d'%i;subnet='172.%d.0'%(30+i)
            command('/usr/sbin/ip','netns','add',ns);namespaces.append(ns)
            command('/usr/sbin/ip','link','add',dev,'type','veth','peer','name',peer);interfaces.append(dev)
            command('/usr/sbin/ip','link','set',peer,'netns',ns)
            command('/usr/sbin/ip','addr','add',subnet+'.1/24','dev',dev)
            command('/usr/sbin/ip','link','set',dev,'up')
            command('/usr/sbin/ip','-n',ns,'link','set','lo','up')
            command('/usr/sbin/ip','-n',ns,'addr','add',subnet+'.2/24','dev',peer)
            command('/usr/sbin/ip','-n',ns,'link','set',peer,'up')
            command('/usr/sbin/tc','qdisc','replace','dev',dev,'root','handle','1:',
                'tbf','rate','100mbit','burst','65536','limit','1048576')
        hostnet=os.open('/proc/self/ns/net',os.O_RDONLY|os.O_CLOEXEC);fds.append(hostnet)
        serverfds=[os.open('/run/netns/cisy7s%d'%i,os.O_RDONLY|os.O_CLOEXEC) for i in range(2)];fds+=serverfds
        root=Path('/sys/fs/cgroup/cis-y7');root.mkdir();(root/'management').mkdir()
        (root/'management/cgroup.procs').write_text(str(os.getpid()))
        (root/'cgroup.subtree_control').write_text('+cpu +memory +cpuset +io')
        roots=[]
        for i in range(4):
            p=root/('root%d'%i);p.mkdir();(p/'memory.max').write_text(str(128<<20));roots.append(p)
        args=SimpleNamespace(worker='/profile/session-worker',residue='/profile/session-residue',bpf='/profile/cis.bpf.o')
        source=source_manifest(args,env['boot_id']);permit=admission.create(source,env,time.monotonic_ns())
        (out/'permit.json').write_text(json.dumps(permit,indent=2))
        cpus=[0,0,1,1];destinations=[0]*4 if arrangement=='shared' else [0,1,0,1]
        plan=dict(schema='cis-y7-queue-plan-v1',source=source,order=order(),arrangement=arrangement,cpus=cpus,
            destinations=destinations,management_cpu=7,clock_ticks=os.sysconf('SC_CLK_TCK'),rounds=3,
            offered=4500,period_ns=2_000_000,timeout_ns=100_000_000,window_ms=2000,payload_bytes=1024,
            egress_rate='100mbit',selected_ifindex=int(Path('/sys/class/net/cisy7ex0/ifindex').read_text()),tx_queue=0,
            schedule='frozen manual profiling slots every 3s; no anomaly-trigger efficacy claim',
            off='idle controller without attached producers',p99='record_only',
            scope='four accounting roots; eight endpoint containers, private UDP sockets; clients share host netns',
            cost_boundary='before endpoint launch through server shutdown and first unified analysis; archive/replay excluded',
            schedstats=Path('/proc/sys/kernel/sched_schedstats').read_text())
        validate_plan(plan);(out/'plan.json').write_text(json.dumps(plan,indent=2))
        daemon=subprocess.Popen(['/usr/bin/python3','/profile/session.py','--socket',endpoint,'--directory',str(out/'records'),
            '--worker',args.worker,'--residue',args.residue,'--bpf',args.bpf,'--admission-policy','prototype',
            '--prototype-permit',str(out/'permit.json'),'daemon'],stdout=log,stderr=log)
        deadline=time.monotonic()+10
        while not Path(endpoint).exists():
            if daemon.poll() is not None or time.monotonic()>deadline: raise RuntimeError('readiness')
            time.sleep(.02)
        targets=[request('register',path=str(p))['target'] for p in roots];states=[]
        for entry in order():
            label=entry['label'];selected=[targets[i] for i in ROLES[entry['round']]]
            before=snap();start=time.monotonic_ns()+1_000_000_000;servers=[];clients=[];sessions=[]
            for i,p in enumerate(roots):
                fd=serverfds[destinations[i]];h=(out/(label+'-server%d.log'%i)).open('x');handles.append(h)
                child=subprocess.Popen(['/session_launch',str(p),str(cpus[i]),'/y7_queue_workload','serve',str(fd),str(i),
                    '172.%d.0.2'%(30+destinations[i]),str(start)],pass_fds=(fd,),stdout=h,stderr=h)
                children.append(child);servers.append(child)
            deadline=time.monotonic()+.7
            while not all(('Y7_QUEUE_READY actor=%d'%i) in (out/(label+'-server%d.log'%i)).read_text() for i in range(4)):
                if any(p.poll() is not None for p in servers) or time.monotonic()>deadline: raise RuntimeError('server readiness')
                time.sleep(.01)
            for i,p in enumerate(roots):
                h=(out/(label+'-client%d.log'%i)).open('x');handles.append(h)
                child=subprocess.Popen(['/session_launch',str(p),str(cpus[i]),'/y7_queue_workload','client',str(hostnet),str(i),
                    '172.%d.0.2'%(30+destinations[i]),str(start)],pass_fds=(hostnet,),stdout=h,stderr=h)
                children.append(child);clients.append(child)
            for slot,collector in enumerate(captures(entry['mode'])):
                due=start+250_000_000+slot*3_000_000_000
                time.sleep(max(0,(due-time.monotonic_ns())/1e9))
                if any(p.poll() is not None for p in clients+servers): raise RuntimeError('business exited before capture')
                kw=dict(cpus=sorted(set(cpus))) if collector=='cpu' else dict(queue=dict(ifindex=plan['selected_ifindex'],tx_queue=0)) if collector=='qdisc' else {}
                sid=request('start',collector=collector,targets=selected,nonce=label+str(slot),window_ms=2000,**kw)['session_id']
                wait(sid,'window');active=observe(collector);wait(sid,'finalized')
                sessions.append(dict(collector=collector,session_id=sid,scheduled_ns=due,active_sources=active,idle_sources=observe(None)))
            codes=[p.wait(timeout=15) for p in clients+servers];after=snap()
            state=dict(**entry,targets=selected,all_targets=targets,start_ns=start,sessions=sessions,
                before=before,after=after,idle_sources=observe(None),exit_codes=codes)
            (out/(label+'-evidence.json')).write_text(json.dumps(state,indent=2))
            records=[json.loads((out/'records'/(s['session_id']+'.json')).read_text()) for s in sessions]
            raws=[(out/'records'/(s['session_id']+'.jsonl')).read_bytes() for s in sessions]
            checked=check(state,[(out/(label+'-client%d.log'%i)).read_text() for i in range(4)],
                [(out/(label+'-server%d.log'%i)).read_text() for i in range(4)],records,raws,plan)
            state['business_after']=after;state['explanation_ready_ns']=time.monotonic_ns()
            state['analysis_process']=dict(status=Path('/proc/self/status').read_text(),
                peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,
                scope='test harness and first unified analysis; cumulative peak')
            state['after']=snap();checked.update(cost_fields(state,plan))
            (out/(label+'-evidence.json')).write_text(json.dumps(state,indent=2))
            (out/(label+'-check.json')).write_text(json.dumps(checked,indent=2))
            states.append(dict(label=label,result=checked['status']));(out/'partial.json').write_text(json.dumps(states,indent=2))
            if checked['status']!='PASS_SCOPED': raise ValueError(checked['errors'])
            del checked,records,raws,state
        (out/'result.json').write_text(json.dumps(dict(status='PASS_SCOPED',states=states,source=source),indent=2))
    finally:
        for p in children:
            if p.poll() is None:p.terminate()
        for p in children:
            try:p.wait(timeout=5)
            except subprocess.TimeoutExpired:p.kill();p.wait()
        if daemon is not None:
            if daemon.poll() is None:daemon.terminate()
            try:daemon.wait(timeout=15)
            except subprocess.TimeoutExpired:daemon.kill();daemon.wait()
        for fd in fds:os.close(fd)
        for h in handles:h.close()
        requests.close();log.close()
        for dev in reversed(interfaces):command('/usr/sbin/ip','link','del',dev)
        for ns in reversed(namespaces):command('/usr/sbin/ip','netns','del',ns)

if __name__=='__main__':run()
