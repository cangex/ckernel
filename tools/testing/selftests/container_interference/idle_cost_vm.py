#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Frozen longer OFF/IDLE comparison; no receipt generation or periodic bypass."""
import json
import os
from pathlib import Path
import socket
import subprocess
import time

PLAN = dict(schema=1, pairs=10, seconds=10, arrival_rate=2000, registered_roots=256,
            workloads=['throughput', 'latency'], modes=['off', 'idle'],
            order='OFF/IDLE on even rounds; IDLE/OFF on odd rounds',
            roles='target and bystander CPU0/2 swap every round',
            cpu_sample_interval_ms=200, snapshot_scope='whole dedicated VM plus two business cgroups',
            throughput_upper95_limit_pct=1, idle_p99_upper95_limit_pct=2,
            physical_cpus_exclusive=False, receipt_generated=False)


def call(endpoint, op, **fields):
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as channel:
        channel.settimeout(2)
        channel.connect(endpoint)
        channel.send(json.dumps(dict(version=1, op=op, **fields)).encode())
        reply = json.loads(channel.recv(8192))
        if not reply['ok']: raise RuntimeError(reply)
        return reply['data']


def snapshot(roots):
    begin = time.monotonic_ns()
    stat = Path('/proc/stat').read_text().splitlines()[0].split()[1:]
    ticks = list(map(int, stat))
    memory = {line.split(':')[0]: int(line.split()[1])*1024
              for line in Path('/proc/meminfo').read_text().splitlines() if line.endswith('kB')}
    usage = []
    for root in roots:
        cpu = dict(line.split() for line in (root/'cpu.stat').read_text().splitlines())
        usage.append(int(cpu['usage_usec']))
    return dict(begin_ns=begin, end_ns=time.monotonic_ns(), cpu_ticks=ticks,
                busy_ticks=sum(ticks[i] for i in (0, 1, 2, 5, 6)),
                hz=os.sysconf('SC_CLK_TCK'), cgroup_usage_us=usage,
                used_vm_bytes=memory['MemTotal']-memory['MemFree'],
                slab_bytes=memory['Slab'], page_tables_bytes=memory['PageTables'],
                kernel_stack_bytes=memory.get('KernelStack'),
                scope='aggregate, not owner attribution; sampled peak is not a hard maximum')


def run():
    if not Path('/cis-disposable-vm').exists() or os.geteuid() or os.uname().machine != 'aarch64':
        raise RuntimeError('isolated ARM64 VM required')
    out = Path('/tmp/idle-cost-evidence')
    out.mkdir(mode=0o700)
    (out/'plan.json').write_text(json.dumps(PLAN, indent=2))
    print('CIS_IDLE_PLAN '+json.dumps(PLAN), flush=True)
    base = Path('/sys/fs/cgroup/cis-idle-cost')
    base.mkdir()
    (base/'management').mkdir()
    (base/'management/cgroup.procs').write_text(str(os.getpid()))
    os.sched_setaffinity(0, {7})
    roots = [base/('root%d' % i) for i in range(PLAN['registered_roots'])]
    for root in roots: root.mkdir()
    endpoint = '/run/cis-idle-cost.sock'
    command = ['/usr/bin/python3', '/profile/session.py', '--socket', endpoint,
               '--directory', str(out/'records'), '--worker', '/profile/session-worker',
               '--bpf', '/profile/cis.bpf.o', '--residue', '/profile/session-residue', 'daemon']
    controller_log = (out/'controller.log').open('x')
    daemon = None
    children, logs = [], []
    try:
        for workload in PLAN['workloads']:
            for repetition in range(PLAN['pairs']):
                for mode in (PLAN['modes'] if repetition % 2 == 0 else PLAN['modes'][::-1]):
                    label = '%s-%02d-%s' % (workload, repetition, mode)
                    before_controller = snapshot(roots[:2])
                    if mode == 'idle':
                        daemon = subprocess.Popen(command, stdout=controller_log, stderr=controller_log)
                        for _ in range(500):
                            try:
                                if call(endpoint, 'status')['state'] == 'IDLE': break
                            except (FileNotFoundError, ConnectionRefusedError): pass
                            if daemon.poll() is not None: raise RuntimeError('controller exited')
                            time.sleep(.01)
                        for root in roots: call(endpoint, 'register', path=str(root))
                        links = [os.readlink(p) for p in Path('/proc/%d/fd' % daemon.pid).iterdir()]
                        assert not any(any(t in link for t in ('perf_event', 'bpf-map', 'bpf-prog')) for link in links)
                    time.sleep(.5)
                    start = time.monotonic_ns()+300_000_000
                    children, logs = [], []
                    for role in range(2):
                        log = (out/('%s-%d.log' % (label, role))).open('x')
                        logs.append(log)
                        cpu = ((role+repetition) % 2)*2
                        cmd = ['/session_launch', str(roots[role]), str(cpu), '/workload',
                               'open-loop' if workload == 'latency' else 'throughput',
                               str(PLAN['seconds']), str(start)]
                        if workload == 'latency': cmd.append(str(PLAN['arrival_rate']))
                        children.append(subprocess.Popen(cmd, stdout=log, stderr=log))
                    observations = []
                    deadline = time.monotonic()+PLAN['seconds']+10
                    while any(child.poll() is None for child in children):
                        if time.monotonic() > deadline: raise TimeoutError(label)
                        observations.append(snapshot(roots[:2]))
                        time.sleep(PLAN['cpu_sample_interval_ms']/1000)
                    assert all(child.returncode == 0 for child in children)
                    for log in logs: log.close()
                    logs = []
                    active_end = snapshot(roots[:2])
                    if daemon is not None:
                        status = call(endpoint, 'status')
                        assert status['sessions'] == [] and not status['periodic_enabled']
                        call(endpoint, 'stop')
                        assert daemon.wait(timeout=10) == 0
                        daemon = None
                    time.sleep(1)
                    report = dict(workload=workload, round=repetition, mode=mode,
                                  start_ns=start, before_controller=before_controller,
                                  samples=observations, active_end=active_end,
                                  after_stop=snapshot(roots[:2]), all_children_exit_zero=True)
                    (out/(label+'.json')).write_text(json.dumps(report))
                    print('CIS_IDLE_TRIAL '+label, flush=True)
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=10)
        if daemon is not None and daemon.poll() is None:
            call(endpoint, 'stop')
            daemon.wait(timeout=10)
        for log in logs: log.close()
        controller_log.close()
    print('CIS_IDLE_COST_COMPLETE=1', flush=True)


if __name__ == '__main__': run()
