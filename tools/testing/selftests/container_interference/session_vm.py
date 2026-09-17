#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run only in the dedicated initramfs. Real container workloads, no host mode."""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument('--stress', type=int, default=100)
parser.add_argument('--cost', action='store_true')
parser.add_argument('--faults', action='store_true')
args = parser.parse_args()
if not Path('/cis-disposable-vm').exists():
    raise SystemExit('dedicated VM marker missing')
OUT = Path('/tmp/session-evidence')
OUT.mkdir()
ROOT = Path('/sys/fs/cgroup/cis-session')
ROOT.mkdir()
(ROOT/'management').mkdir()
(ROOT/'management/cgroup.procs').write_text(str(os.getpid()))
os.sched_setaffinity(0, {7})
SOCK = '/run/profile.sock'
DAEMON = ['/usr/bin/python3', '/profile/session.py', '--socket', SOCK,
          '--directory', str(OUT/'records'), '--worker', '/profile/session-worker',
          '--bpf', '/profile/cis.bpf.o', '--residue', '/profile/session-residue', '--test-faults', 'daemon']
daemon_log = (OUT/'controller.log').open('w')
daemon = subprocess.Popen(DAEMON, stdout=daemon_log, stderr=daemon_log)
for _ in range(500):
    if Path(SOCK).exists(): break
    if daemon.poll() is not None: raise RuntimeError('daemon died')
    time.sleep(.01)


def request(op, **fields):
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as conn:
        conn.settimeout(15)
        conn.connect(SOCK)
        conn.send(json.dumps(dict(version=1, op=op, **fields)).encode())
        result = json.loads(conn.recv(8192))
        if not result['ok']: raise RuntimeError(result)
        return result['data']


def finished(sid, allow_fault=False):
    until = time.monotonic()+20
    while time.monotonic()<until:
        record = request('status', session=sid)
        if record.get('finalized') and record['state'] in ('IDLE', 'FAULTED'):
            if (record['state'] != 'IDLE' and not allow_fault) or not record.get('objects_absent'):
                raise AssertionError(record)
            return record
        time.sleep(.02)
    raise TimeoutError(sid)


targets=[]
for i in range(256):
    path = ROOT/('root%d' % i)
    path.mkdir()
    targets.append(request('register', path=str(path))['target'])
    if i in (0,127,255):
        fdlinks = [os.readlink(p) for p in Path('/proc/%d/fd' % daemon.pid).iterdir()]
        bad = [v for v in fdlinks if any(s in v for s in ('perf_event','bpf-map','bpf-prog','cpu.pressure','memory.pressure'))]
        assert not bad, bad
        print('CIS_PROFILE_IDLE '+json.dumps({'roots':i+1,'fd_count':len(fdlinks),'sampler_fds':bad}),flush=True)
before_fds=len(list(Path('/proc/%d/fd' % daemon.pid).iterdir()))
before_ticks=Path('/proc/%d/stat' % daemon.pid).read_text().rsplit(')',1)[1].split()[11:13]
time.sleep(2)
after_ticks=Path('/proc/%d/stat' % daemon.pid).read_text().rsplit(')',1)[1].split()[11:13]
print('CIS_PROFILE_IDLE_CPU '+json.dumps({'before':before_ticks,'after':after_ticks,'seconds':2}),flush=True)

def launch(label, mode, start, seconds=2, scenario=None):
    children=[]
    for i in range(2):
        log=(OUT/('%s-%d.log' % (label,i))).open('w')
        command=['/session_launch',str(ROOT/('root%d'%i)),str(i*2),'/workload',mode,str(seconds),str(start)]
        if scenario is not None:
            command=['/session_launch',str(ROOT/('root%d'%i)),str(0 if scenario=='preempt' else i*2),
                     '/workload','fixture',str(i if scenario=='private' else 0),str(start),scenario]
        children.append((subprocess.Popen(command,stdout=log,stderr=log),log))
    return children


def join(children):
    for child,log in children:
        code=child.wait(timeout=20);log.close()
        assert code==0,code


def begin(collector, nonce, target_count=2, **extra):
    return request('start',collector=collector,nonce=nonce,targets=targets[:target_count],window_ms=2000,**extra)


def window(sid):
    for _ in range(1000):
        state=request('status',session=sid)
        if 'window' in state: return state['window']['start_ns']
        if state['state'] in ('IDLE','FAULTED'): raise AssertionError(state)
        time.sleep(.005)
    raise TimeoutError('arming')


# Real sampled IP and bounded owner fixtures are separate from empty-root lifecycle stress.
before=time.monotonic_ns()
sid=begin('ip','cancelSlowAdmission',inject='admission_slow')['session_id']
response_ns=time.monotonic_ns()-before
record=request('status',session=sid)
assert 'worker_pid' not in record, record
request('cancel',session=sid)
assert finished(sid)['result']=='CANCELLED'
print('CIS_PROFILE_ADMISSION '+json.dumps(dict(slow_io_cancelled=True,
      start_response_ns=response_ns, worker_never_spawned=request('status',session=sid)['worker_never_spawned'])),flush=True)

for kind in ('ip','owner'):
    sid=begin(kind,'functional'+kind)['session_id']
    start=window(sid)
    children=launch(kind,'throughput',start,scenario='shared' if kind=='owner' else None)
    join(children)
    record=finished(sid)
    print('CIS_PROFILE_FUNCTION '+json.dumps(record),flush=True)
    assert record['result']=='COMPLETE', record
    duplicate=begin(kind,'functional'+kind)
    assert duplicate['session_id']==sid
    request('cancel',session=sid)

for scenario in ('private','reuse','preempt'):
    sid=begin('owner','fixture'+scenario)['session_id']
    children=launch(scenario,'fixture',window(sid),scenario=scenario)
    join(children)
    record=finished(sid)
    print('CIS_PROFILE_NEGATIVE '+json.dumps(record),flush=True)
    assert record['result']=='COMPLETE', record

sid=begin('ip','inject',inject='after_prepare')['session_id']
assert finished(sid)['result']=='PARTIAL'
sid=begin('owner','cancelPrepare')['session_id']
request('cancel',session=sid)
assert finished(sid)['result']=='CANCELLED'
sid=begin('ip','cancelActive')['session_id']
window(sid);request('cancel',session=sid);request('cancel',session=sid)
assert finished(sid)['result']=='CANCELLED'

for kind in ('ip','owner'):
    for i in range(args.stress):
        sid=begin(kind,'repeat%s%d'%(kind,i))['session_id']
        record=finished(sid)
        assert record['receipt']['stop_error']==0
        assert record['inventory']['ip_perf_cpus']==0 if kind=='owner' else record['inventory']['ip_perf_cpus']>0
        if i%10==0: print('CIS_PROFILE_STRESS '+json.dumps({'collector':kind,'iteration':i,'result':record['result']}),flush=True)
assert len(list(Path('/proc/%d/fd' % daemon.pid).iterdir()))==before_fds

if args.cost:
    # Predeclared five pairs, opposite orders. Separate closed/open loop workloads.
    for workload in ('throughput','latency'):
        for repetition in range(5):
            order=['off','idle','ip','owner'] if repetition%2==0 else ['owner','ip','idle','off']
            for mode in order:
                label='cost-%s-%d-%s'%(workload,repetition,mode)
                if mode=='off':
                    request('stop');assert daemon.wait(timeout=10)==0
                sid=None
                if mode in ('ip','owner'):
                    sid=begin(mode,label.replace('-',''),target_count=1)['session_id'];start=window(sid)
                else:
                    start=time.monotonic_ns()+100_000_000
                children=launch(label,'open-loop' if workload=='latency' else 'throughput',start)
                join(children)
                for role in range(2):
                    output=(OUT/('%s-%d.log'%(label,role))).read_text()
                    assert ('CIS_LATENCY ' if workload=='latency' else 'CIS_RESULT ') in output
                if sid: finished(sid)
                if mode=='off':
                    daemon=subprocess.Popen(DAEMON,stdout=daemon_log,stderr=daemon_log)
                    for _ in range(500):
                        if Path(SOCK).exists():break
                        time.sleep(.01)
                    targets=[request('register',path=str(ROOT/('root%d'%i)))['target'] for i in range(2)]
                print('CIS_PROFILE_COST '+label,flush=True)
if args.faults:
    sid=begin('owner','workerCrash')['session_id'];window(sid)
    os.kill(request('status',session=sid)['worker_pid'],signal.SIGKILL)
    assert finished(sid)['result']=='FAILED'
    print('CIS_PROFILE_FAULT worker_crash_cleaned=1',flush=True)
    sid=begin('ip','workerStop')['session_id'];window(sid)
    os.kill(request('status',session=sid)['worker_pid'],signal.SIGSTOP)
    record=finished(sid,allow_fault=True)
    assert record['state']=='FAULTED'
    request('recover')
    print('CIS_PROFILE_FAULT worker_stop_faulted_recovered=1',flush=True)
    sid=begin('owner','controllerStop')['session_id'];window(sid)
    os.kill(daemon.pid,signal.SIGSTOP);time.sleep(2.5);os.kill(daemon.pid,signal.SIGCONT)
    assert finished(sid)['result']=='COMPLETE'
    print('CIS_PROFILE_FAULT controller_stop_worker_deadline=1',flush=True)
    for both in (False,True):
        sid=begin('ip','bothCrash' if both else 'controllerCrash')['session_id'];window(sid)
        worker=request('status',session=sid)['worker_pid']
        if both:os.kill(worker,signal.SIGKILL)
        os.kill(daemon.pid,signal.SIGKILL);daemon.wait(timeout=10)
        for _ in range(500):
            if not Path('/proc/%d'%worker).exists():break
            time.sleep(.01)
        daemon=subprocess.Popen(DAEMON,stdout=daemon_log,stderr=daemon_log)
        # The old socket path remains until the new daemon replaces it.
        for _ in range(500):
            try:
                if request('status')['state']=='FAULTED':break
            except (ConnectionRefusedError,FileNotFoundError):pass
            time.sleep(.01)
        assert request('status')['state']=='FAULTED'
        request('recover')
        targets=[request('register',path=str(ROOT/('root%d'%i)))['target'] for i in range(2)]
        print('CIS_PROFILE_FAULT '+('both_crash' if both else 'controller_crash')+'_faulted_recovered=1',flush=True)
request('stop');assert daemon.wait(timeout=10)==0
daemon_log.close()
print('CIS_PROFILE_VM_FUNCTIONAL_PASS=1',flush=True)
