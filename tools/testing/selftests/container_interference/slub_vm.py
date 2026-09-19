#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Dedicated-VM real node-lock truth and ordinary SLUB operation bridge."""
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

CASES = ('shared', 'private', 'switch', 'recreate', 'unseenHolder', 'native')


def run():
    os.umask(0o077); os.sched_setaffinity(0, {7})
    env = admission.environment(); admission.check_environment(env)
    out = Path('/tmp/slub-evidence'); out.mkdir(mode=0o700)
    root = Path('/sys/fs/cgroup/cis-slub'); root.mkdir(); (root/'management').mkdir()
    (root/'management/cgroup.procs').write_text(str(os.getpid()))
    (root/'cgroup.subtree_control').write_text('+cpu +memory +cpuset')
    roots = []
    for i in range(4):
        p = root/('root%d'%i); p.mkdir(); (p/'memory.max').write_text(str(64<<20)); roots.append(p)
    args = SimpleNamespace(worker='/profile/session-worker', residue='/profile/session-residue', bpf='/profile/cis.bpf.o')
    source = source_manifest(args, env['boot_id']); permit = admission.create(source, env, time.monotonic_ns())
    (out/'permit.json').write_text(json.dumps(permit, indent=2))
    plan = dict(schema='cis-slub-vm-plan-v2', cases=list(CASES), rounds=3, source=source,
        window_ms=2000, hold_us=5000, target_indices=[0,1], registered_roots=4,
        eligible_min_overlap_ns=100_000, cpus=[0,1,2,3], nodes=[0,1],
        order='OFF_ON,ON_OFF,OFF_ON', recreated_watch='target warmup before non-target holder',
        scope='controlled real node-lock truth; native operation bridge and unobserved acquire separate')
    (out/'plan.json').write_text(json.dumps(plan, indent=2))
    endpoint = '/run/cis-slub.sock'; log = (out/'controller.log').open('x')
    requests = (out/'requests.jsonl').open('x')
    daemon = subprocess.Popen(['/usr/bin/python3','/profile/session.py','--socket',endpoint,'--directory',str(out/'records'),
        '--worker',args.worker,'--residue',args.residue,'--bpf',args.bpf,'--admission-policy','prototype',
        '--prototype-permit',str(out/'permit.json'),'daemon'], stdout=log, stderr=log)
    children = []; handles = []; states = []; token = 0

    def request(op, **kw):
        req = dict(version=1, op=op, **kw); before = time.monotonic_ns()
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as sock:
            sock.settimeout(15); sock.connect(endpoint); sock.send(json.dumps(req).encode()); reply=json.loads(sock.recv(16384))
        retained = reply
        if op == 'status' and reply.get('ok'):
            retained = dict(reply, data={k:reply['data'][k] for k in ('state','session_id','finalized') if k in reply['data']})
        requests.write(json.dumps(dict(before_ns=before, after_ns=time.monotonic_ns(), request=req, response=retained))+'\n'); requests.flush()
        if not reply['ok']: raise RuntimeError(reply)
        return reply['data']

    def wait(sid, key):
        deadline = time.monotonic()+20
        while time.monotonic() < deadline:
            r = request('status', session=sid)
            if r.get(key): return r
            if r.get('finalized'): raise RuntimeError(r)
            time.sleep(.02 if key == 'window' else .1)
        raise TimeoutError(sid)

    def finish(p):
        if p.wait(timeout=5): raise RuntimeError('fixture exit '+str(p.returncode))

    try:
        deadline = time.monotonic()+10
        while not Path(endpoint).exists():
            if daemon.poll() is not None or time.monotonic()>deadline: raise RuntimeError('readiness')
            time.sleep(.02)
        registered = [request('register', path=str(p))['target'] for p in roots]
        targets = registered[:2]; observe(None)
        for repeat in range(3):
            for case in CASES:
                for enabled in ((False,True) if repeat%2==0 else (True,False)):
                    label = '%s%d-%s'%(case,repeat,'on' if enabled else 'off')
                    token += 1; jobs=[]; begin=len(children); sid=None; window=None

                    def start(suffix, actor, command='operate', node=0, hold=0, wait_node=0, wait_holders=0, mode=0):
                        name=label+'-'+suffix+'.log'; handle=(out/name).open('x'); handles.append(handle)
                        arguments=dict(command=command,node=node,hold=hold,wait_node=wait_node,wait_holders=wait_holders,mode=mode)
                        jobs.append(dict(log=name,actor_index=actor,token=token,arguments=arguments))
                        p=subprocess.Popen(['/session_launch',str(roots[actor]),str(actor),'/slub_workload',command,
                            str(token),str(node),str(hold),str(wait_node),str(wait_holders),str(mode)],stdout=handle,stderr=handle)
                        children.append(p); return p

                    if enabled:
                        sid=request('start',collector='slub',targets=targets,nonce=label.replace('-',''),window_ms=2000)['session_id']
                        window=wait(sid,'window')['window']; active=observe('slub')
                        delay=(window['start_ns']+20_000_000-time.monotonic_ns())/1e9
                        if delay>0: time.sleep(delay)
                    else: active=observe(None)
                    finish(start('reset',0,command='reset'))
                    if case=='native':
                        start('native0',0,mode=1); start('native1',1,mode=1)
                    else:
                        # Start the waiter first. Its bounded in-kernel rendezvous
                        # observes a real acquisition before attempting the lock.
                        w=start('waiter0',1,node=1 if case=='private' else 0,wait_holders=1)
                        h=start('holder0',2 if case=='unseenHolder' else 0,hold=5000); finish(h); finish(w)
                        if case in ('switch','recreate'):
                            token+=1
                            finish(start('reset2',0,command='recreate' if case=='recreate' else 'reset'))
                            if case=='recreate':
                                # New object watches are target-opened. Cover the
                                # missing-acquire case separately, never infer it.
                                finish(start('warmup',0))
                            w=start('waiter1',1,wait_holders=2 if case=='recreate' else 1)
                            h=start('holder1',2,hold=5000); finish(h); finish(w)
                    for p in children[begin:]: finish(p)
                    if enabled:
                        if time.monotonic_ns()>=window['end_ns']: raise RuntimeError('work beyond window')
                        row=wait(sid,'finalized')
                        if not row.get('objects_absent'): raise RuntimeError('cleanup')
                    idle=observe(None)
                    state=dict(label=label,case=case,round=repeat,enabled=enabled,session_id=sid,
                        jobs=jobs,registered=registered,targets=targets,active_sources=active,idle_sources=idle,
                        exit_codes=[p.returncode for p in children[begin:]])
                    states.append(state); (out/(label+'-evidence.json')).write_text(json.dumps(state,indent=2))
                    (out/'partial.json').write_text(json.dumps(states,indent=2))
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


if __name__=='__main__': run()
