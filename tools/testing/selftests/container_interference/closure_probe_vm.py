#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Fixed diagnostic only: cgroup accounting plus guest scheduling timelines."""
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time

from session_quality import assess

if not Path('/cis-disposable-vm').exists() or os.geteuid() != 0:
    raise SystemExit('dedicated disposable VM required')
os.sched_setaffinity(0, {7})
OUT = Path('/tmp/closure-evidence'); OUT.mkdir()
ROOT = Path('/sys/fs/cgroup/cis-closure'); ROOT.mkdir()
(ROOT/'cgroup.subtree_control').write_text('+cpu +memory')
MGMT = ROOT/'management'; MGMT.mkdir()
(MGMT/'cgroup.procs').write_text(str(os.getpid()))
BUSINESS = [ROOT/('root%d' % i) for i in range(2)]
for path in BUSINESS:
    path.mkdir()
TRACE = Path('/sys/kernel/tracing/instances/cis-closure'); TRACE.mkdir()
SOCK = '/run/closure.sock'
stage_errors = []


def kv(path):
    return {k: int(v) for k, v in (line.split() for line in path.read_text().splitlines())}


def snapshot(observer):
    before = time.monotonic_ns()
    def group(path):
        return dict(memory_current=int((path/'memory.current').read_text()),
                    memory_peak=int((path/'memory.peak').read_text()),
                    memory_stat=kv(path/'memory.stat'), memory_events=kv(path/'memory.events'),
                    cpu_stat=kv(path/'cpu.stat'))
    try:
        value = dict(time_ns=before, errors=[],
                    observer=group(observer), management=group(MGMT),
                    business=[group(p) for p in BUSINESS],
                    proc_stat=Path('/proc/stat').read_text(), meminfo=Path('/proc/meminfo').read_text())
        value['end_ns'] = time.monotonic_ns()
        return value
    except (OSError, ValueError) as error:
        return dict(time_ns=before, errors=[str(error)])


class Sampler:
    def __init__(self, path):
        self.path = path; self.samples = [snapshot(path)]; self.cpu_ns = 0
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run)

    def run(self):
        start = time.thread_time_ns()
        # Bounded diagnostic observer, excluded from observer-cgroup accounting.
        for _ in range(1200):
            if self.stop.wait(.1):
                break
            self.samples.append(snapshot(self.path))
        else:
            stage_errors.append('resource sampler time bound')
        self.cpu_ns = time.thread_time_ns() - start

    def finish(self):
        self.stop.set(); self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError('sampler did not stop')
        self.samples.append(snapshot(self.path))


def request(op, **fields):
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as conn:
        conn.settimeout(15); conn.connect(SOCK)
        conn.send(json.dumps(dict(version=1, op=op, **fields)).encode())
        result = json.loads(conn.recv(8192))
        if not result['ok']:
            raise RuntimeError(result)
        return result['data']


def start_daemon(observer, directory):
    log = (directory/'controller.log').open('w')
    command = ['/usr/bin/python3', '/profile/session.py', '--socket', SOCK,
               '--directory', str(directory/'records'), '--worker', '/profile/session-worker',
               '--bpf', '/profile/cis.bpf.o', '--residue', '/profile/session-residue', 'daemon']
    # No preexec_fn in a multi-threaded parent. This fresh helper moves itself
    # and then execs, so worker descendants inherit the same accounting boundary.
    helper = ('import os,sys; '
              'f=os.open(sys.argv[1],os.O_WRONLY); os.write(f,str(os.getpid()).encode()); '
              'os.close(f); os.execv(sys.argv[2],sys.argv[2:])')
    proc = subprocess.Popen(['/usr/bin/python3', '-c', helper, str(observer/'cgroup.procs')] + command,
                            stdout=log, stderr=log)
    for _ in range(500):
        if proc.poll() is not None:
            raise RuntimeError('daemon exited before ready')
        try:
            request('status'); return proc, log
        except (ConnectionRefusedError, FileNotFoundError):
            time.sleep(.01)
    raise TimeoutError('daemon ready')


def trace_start(pids):
    (TRACE/'tracing_on').write_text('0')
    (TRACE/'current_tracer').write_text('nop')
    (TRACE/'buffer_size_kb').write_text('1024')
    (TRACE/'trace_clock').write_text('mono')
    (TRACE/'trace').write_text('')
    filters = {'sched_waking': ' || '.join('pid==%d' % p for p in pids),
               'sched_switch': ' || '.join('(prev_pid==%d || next_pid==%d)' % (p,p) for p in pids)}
    for event, expr in filters.items():
        node = TRACE/'events/sched'/event
        (node/'filter').write_text(expr); (node/'enable').write_text('1')
    (TRACE/'tracing_on').write_text('1')
    return time.monotonic_ns()


def trace_stop(directory, pids, begin):
    (TRACE/'tracing_on').write_text('0'); end = time.monotonic_ns()
    for event in ('sched_waking', 'sched_switch'):
        (TRACE/'events/sched'/event/'enable').write_text('0')
    stats = {}
    for path in sorted((TRACE/'per_cpu').glob('cpu*/stats')):
        row = {}
        for line in path.read_text().splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                if value.strip().isdigit(): row[key.strip()] = int(value.strip())
        stats[path.parent.name] = row
    with (TRACE/'trace').open() as stream:
        trace = stream.read(8*1024*1024+1)
    truncated = len(trace) > 8*1024*1024
    (directory/'schedule.trace').write_text(trace[:8*1024*1024])
    meta = dict(diagnostic_only=True, clock='mono', host_pids=pids, cpu_stats=stats,
                trace_begin_ns=begin, trace_end_ns=end, truncated=truncated,
                buffer_kb_per_cpu=1024, cpu_count=len(stats))
    (directory/'schedule.json').write_text(json.dumps(meta, indent=2))
    return meta


def trial(index, mode, timer):
    directory = OUT/('%02d-%s-%s' % (index, timer, mode)); directory.mkdir()
    observer = ROOT/('observer%d' % index); observer.mkdir()
    sampler = Sampler(observer); stages = dict(before_start_ns=time.monotonic_ns())
    sampler.thread.start(); daemon = None; children = []; tracing = False
    controller_log = None; record = None; quality = None
    try:
        if mode != 'off':
            daemon, controller_log = start_daemon(observer, directory)
            targets = [request('register', path=str(p))['target'] for p in BUSINESS]
            stages['daemon_ready_ns'] = time.monotonic_ns()
        sid = None
        if mode in ('ip', 'owner'):
            sid = request('start', collector=mode, nonce='closure%d' % index,
                          targets=targets[:1], window_ms=2000)['session_id']
            for _ in range(1000):
                status = request('status', session=sid)
                if 'window' in status:
                    start = status['window']['start_ns']; break
                if status['state'] in ('IDLE','FAULTED'):
                    raise RuntimeError(status)
                time.sleep(.005)
            else: raise TimeoutError('arm')
        else:
            start = time.monotonic_ns()+500_000_000
        stages['workload_start_ns'] = start
        for role in range(2):
            log = (directory/('workload%d.log' % role)).open('w')
            cmd = ['/session_launch', str(BUSINESS[role]), str(role*2), '/workload',
                   'open-loop','2',str(start),'2000','timeline']
            if timer == 'slack1': cmd.append('slack1')
            children.append((subprocess.Popen(cmd,stdout=log,stderr=log), log))
        pids = []
        for path in BUSINESS:
            for _ in range(100):
                values = (path/'cgroup.procs').read_text().split()
                if len(values) == 1:
                    pids.append(int(values[0])); break
                time.sleep(.001)
            else: raise RuntimeError('one container task required')
        trace_begin = trace_start(pids); tracing = True
        for proc, log in children:
            if proc.wait(timeout=15) != 0: raise RuntimeError('workload failure')
            log.close()
        meta = trace_stop(directory, pids, trace_begin); tracing = False
        stages['workload_end_ns'] = time.monotonic_ns()
        if sid:
            for _ in range(1000):
                record = request('status', session=sid)
                if record.get('finalized') and record['state'] in ('IDLE', 'FAULTED'): break
                time.sleep(.01)
            else: raise TimeoutError('session finalized')
            quality = assess(record)
            (directory/'session-quality.json').write_text(json.dumps(quality, indent=2))
        if daemon:
            request('stop')
            if daemon.wait(timeout=15) != 0: raise RuntimeError('daemon exit')
            controller_log.close()
        stages['daemon_exit_ns'] = time.monotonic_ns()
        time.sleep(5)
        stages['tail_end_ns'] = time.monotonic_ns()
    finally:
        if tracing:
            (TRACE/'tracing_on').write_text('0')
            for event in ('sched_waking','sched_switch'):
                (TRACE/'events/sched'/event/'enable').write_text('0')
        for proc, log in children:
            if proc.poll() is None: proc.terminate(); proc.wait(timeout=5)
            log.close()
        if daemon and daemon.poll() is None:
            daemon.terminate(); daemon.wait(timeout=10)
        if controller_log: controller_log.close()
        sampler.finish()
        result = dict(schema='cis-resource-timeline-v1', diagnostic_only=True, mode=mode,
                      timer_control=timer, stages=stages, samples=sampler.samples,
                      sampler_thread_cpu_ns=sampler.cpu_ns,
                      limits='memcg charged memory only; sampler and trace are extra diagnostic overhead')
        (directory/'resources.json').write_text(json.dumps(result, indent=2))
    print('CIS_CLOSURE_TRIAL '+json.dumps(dict(index=index, mode=mode, timer=timer,
          quality=quality, trace_truncated=meta['truncated'], directory=str(directory))), flush=True)


manifest = dict(schema='cis-closure-probe-plan-v1', diagnostic_only=True,
                sequence=[(t,m) for t, modes in [('default', ['off','idle','ip','owner']),
                          ('slack1', ['owner','ip','idle','off'])] for m in modes],
                rounds_per_cell=1, window_ms=2000, arrival_rate=2000, tail_s=5,
                syscall_work='open/fstat/close', observer_roots=2,
                kernel_release=os.uname().release,
                kernel_notes_sha256=hashlib.sha256(Path('/sys/kernel/notes').read_bytes()).hexdigest(),
                cmdline=Path('/proc/cmdline').read_text(),
                note='timer control and traced batch must not replace default untraced acceptance')
(OUT/'plan.json').write_text(json.dumps(manifest, indent=2))
for index, (timer, mode) in enumerate(manifest['sequence']):
    trial(index, mode, timer)
if stage_errors: raise RuntimeError(stage_errors)
print('CIS_CLOSURE_PROBE_DONE=1', flush=True)
