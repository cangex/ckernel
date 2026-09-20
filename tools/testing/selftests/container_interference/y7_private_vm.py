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
from joint_costs import snapshot
from session import source_manifest
from source_switches import observe
from y7_private_check import order,captures,check,cost_fields,ROLES

def run():
    os.umask(0o077);os.sched_setaffinity(0,{7})
    env=admission.environment();admission.check_environment(env)
    arrangement=Path('/y7-arrangement').read_text().strip()
    if not Path('/cis-disposable-vm').exists() or arrangement not in ('shared','separate'):
        raise PermissionError('frozen disposable cohort required')
    out=Path('/tmp/y7-private-evidence');out.mkdir(mode=0o700)
    endpoint='/run/cis-y7.sock';children=[];handles=[];fds=[];daemon=None
    requests=(out/'requests.jsonl').open('x');log=(out/'controller.log').open('x')
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
    try:
        root=Path('/sys/fs/cgroup/cis-y7');root.mkdir();(root/'management').mkdir()
        (root/'management/cgroup.procs').write_text(str(os.getpid()))
        (root/'cgroup.subtree_control').write_text('+cpu +memory +cpuset +io')
        roots=[];directories=[]
        for i in range(4):
            p=root/('root%d'%i);p.mkdir();(p/'memory.max').write_text(str(128<<20));roots.append(p)
            disk=0 if arrangement=='shared' else i%2
            directory=Path('/fs%d/private%d'%(disk,i));directory.mkdir()
            fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC);fds.append(fd);st=os.fstat(fd)
            directories.append(dict(path=str(directory),dev=st.st_dev,inode=st.st_ino,disk=disk))
        args=SimpleNamespace(worker='/profile/session-worker',residue='/profile/session-residue',bpf='/profile/cis.bpf.o')
        source=source_manifest(args,env['boot_id']);permit=admission.create(source,env,time.monotonic_ns())
        (out/'permit.json').write_text(json.dumps(permit,indent=2))
        cpus=[0,0,1,1] if arrangement=='shared' else [0,1,2,3]
        plan=dict(schema='cis-y7-private-plan-v1',source=source,order=order(),arrangement=arrangement,
            directories=directories,cpus=cpus,management_cpu=7,clock_ticks=os.sysconf('SC_CLK_TCK'),
            rounds=3,offered=6000,period_ns=3_000_000,timeout_ns=100_000_000,window_ms=2000,
            schedule='frozen manual profiling slots every 3s; no anomaly-trigger efficacy claim',
            off='idle controller without attached producers',p99='record_only',
            scope='four real containers, private files and anonymous VMAs; no injected lock delays',
            comparisons='within arrangement only; CPU and disk layouts are not independent causal interventions',
            cost_boundary='before launch through first unified analysis; final archive serialization and independent replay excluded',
            mounts=Path('/proc/self/mountinfo').read_text(),schedstats=Path('/proc/sys/kernel/sched_schedstats').read_text())
        (out/'plan.json').write_text(json.dumps(plan,indent=2))
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
            before=snapshot(root,roots);start=time.monotonic_ns()+500_000_000;running=[];sessions=[]
            for i,p in enumerate(roots):
                h=(out/(label+'-%d.log'%i)).open('x');handles.append(h)
                child=subprocess.Popen(['/session_launch',str(p),str(cpus[i]),'/y7_private_workload',str(fds[i]),str(i),str(start)],
                    pass_fds=(fds[i],),stdout=h,stderr=h);children.append(child);running.append(child)
            for slot,collector in enumerate(captures(entry['mode'])):
                due=start+250_000_000+slot*3_000_000_000
                time.sleep(max(0,(due-time.monotonic_ns())/1e9))
                if any(p.poll() is not None for p in running): raise RuntimeError('business exited before capture')
                kwargs=dict(cpus=sorted(set(cpus))) if collector=='cpu' else dict(filesystem='/fs0') if collector=='filesystem' else {}
                sid=request('start',collector=collector,targets=selected,nonce=label+str(slot),window_ms=2000,**kwargs)['session_id']
                wait(sid,'window');active=observe(collector);wait(sid,'finalized')
                sessions.append(dict(collector=collector,session_id=sid,scheduled_ns=due,active_sources=active,idle_sources=observe(None)))
            codes=[p.wait(timeout=25) for p in running];after=snapshot(root,roots)
            state=dict(**entry,targets=selected,all_targets=targets,start_ns=start,sessions=sessions,
                before=before,after=after,idle_sources=observe(None),exit_codes=codes)
            (out/(label+'-evidence.json')).write_text(json.dumps(state,indent=2))
            records=[json.loads((out/'records'/(s['session_id']+'.json')).read_text()) for s in sessions]
            raws=[(out/'records'/(s['session_id']+'.jsonl')).read_bytes() for s in sessions]
            checked=check(state,[(out/(label+'-%d.log'%i)).read_text() for i in range(4)],records,raws,plan)
            state['business_after']=after
            state['explanation_ready_ns']=time.monotonic_ns()
            state['after']=snapshot(root,roots)
            checked.update(cost_fields(state,plan))
            (out/(label+'-evidence.json')).write_text(json.dumps(state,indent=2))
            (out/(label+'-check.json')).write_text(json.dumps(checked,indent=2))
            states.append(dict(label=label,result=checked['status']));(out/'partial.json').write_text(json.dumps(states,indent=2))
            if checked['status']!='PASS_SCOPED': raise ValueError(checked['errors'])
        (out/'result.json').write_text(json.dumps(dict(status='PASS_SCOPED',states=states,source=source),indent=2))
    finally:
        for p in children:
            if p.poll() is None: p.terminate()
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

if __name__=='__main__':run()
