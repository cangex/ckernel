#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""No collector or trace in the fixed OFF/OFF experiment."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

from repeatability_report import PROTOCOL


def run(boot):
    if not Path('/cis-disposable-vm').exists() or os.geteuid() or os.uname().machine != 'aarch64':
        raise RuntimeError('dedicated ARM64 VM required')
    if boot not in (0, 1):
        raise ValueError('boot index must be 0 or 1')
    os.sched_setaffinity(0, {7})
    out = Path('/tmp/repeatability'); out.mkdir()
    root = Path('/sys/fs/cgroup/cis-repeatability'); root.mkdir()
    management = root/'management'; management.mkdir()
    (management/'cgroup.procs').write_text(str(os.getpid()))
    (root/'cgroup.subtree_control').write_text('+cpu +memory')
    groups = [root/('role%d' % i) for i in range(2)]
    for group in groups: group.mkdir()
    paths = dict(workload_sha256='/container-root/workload', launcher_sha256='/session_launch',
                 kernel_notes_sha256='/sys/kernel/notes', cmdline_sha256='/proc/cmdline', runner_sha256=__file__)
    plan = dict(protocol=PROTOCOL, boot_index=boot, boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                source={k: hashlib.sha256(Path(p).read_bytes()).hexdigest() for k,p in paths.items()})
    (out/'plan.json').write_text(json.dumps(plan, indent=2))
    print('CIS_REPEATABILITY_PLAN '+json.dumps(plan), flush=True)
    for workload in ('throughput', 'latency'):
        for pair in range(5):
            for label in (('A', 'B') if (boot*5+pair)%2 == 0 else ('B', 'A')):
                start = time.monotonic_ns()+500_000_000
                children = []
                try:
                    for role in range(2):
                        cpu = (role ^ ((boot*5+pair)%2))*2
                        path = out/('%s-%d-%s-%d.log' % (workload,pair,label,role))
                        log = path.open('x')
                        cmd = ['/session_launch', str(groups[role]), str(cpu), '/workload',
                               'throughput' if workload=='throughput' else 'open-loop', '2', str(start)]
                        if workload=='latency': cmd.append('2000')
                        cmd.append('warm4096')
                        child = subprocess.Popen(cmd, stdout=log, stderr=log)
                        children.append((child, log, dict(workload=workload, pair=pair, label=label,
                                         role=role, cpu=cpu, path=str(path), start_ns=start)))
                    for child, log, case in children:
                        rc = child.wait(timeout=20)
                        log.close(); case['exit_code'] = rc
                        print('CIS_REPEATABILITY_CASE '+json.dumps(case), flush=True)
                        if rc: raise RuntimeError('failed workload; fixed batch is incomplete')
                finally:
                    for child, log, _ in children:
                        if child.poll() is None:
                            child.terminate(); child.wait(timeout=5)
                        log.close()
    print('CIS_REPEATABILITY_DONE=0', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--boot-index', type=int, required=True)
    run(parser.parse_args().boot_index)
