#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Dedicated-VM periodic functional test, not a performance acceptance run.

Default: prove missing P1 evidence prevents sampling. Positive mode requires a
real P1 receipt; this program never constructs or changes that receipt.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import time


def request(endpoint, op, **fields):
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as connection:
        connection.settimeout(15)
        connection.connect(endpoint)
        connection.send(json.dumps(dict(version=1, op=op, **fields)).encode())
        return json.loads(connection.recv(8192))


def run(args):
    if not Path('/cis-disposable-vm').exists() or os.geteuid() or os.uname().machine != 'aarch64':
        raise RuntimeError('dedicated ARM64 VM required; never run on the host')
    if args.cycles < 2 or args.cycles > 3:
        raise ValueError('two or three real 60s cycles supported by this functional fixture')
    stamp = str(time.monotonic_ns())
    out = Path('/tmp')/('periodic-evidence-'+stamp)
    out.mkdir(mode=0o700)
    root = Path('/sys/fs/cgroup')/('cis-periodic-'+stamp)
    root.mkdir()
    (root/'management').mkdir()
    (root/'management/cgroup.procs').write_text(str(os.getpid()))
    os.sched_setaffinity(0, {7})
    endpoint = '/run/profile-periodic-'+stamp+'.sock'
    command = ['/usr/bin/python3', '/profile/session.py', '--socket', endpoint,
               '--directory', str(out/'records'), '--worker', '/profile/session-worker',
               '--bpf', '/profile/cis.bpf.o', '--residue', '/profile/session-residue']
    if args.p1_acceptance:
        command += ['--p1-acceptance', str(Path(args.p1_acceptance).resolve())]
    command.append('daemon')
    children, logs = [], []
    controller_log = (out/'controller.log').open('x')
    daemon = subprocess.Popen(command, stdout=controller_log, stderr=controller_log)

    def call(op, **fields):
        result = request(endpoint, op, **fields)
        if not result['ok']:
            raise RuntimeError(result)
        return result['data']

    try:
        for _ in range(500):
            if Path(endpoint).exists(): break
            if daemon.poll() is not None: raise RuntimeError('controller failed')
            time.sleep(.01)
        targets = []
        for i in range(2):
            path = root/('root%d' % i)
            path.mkdir()
            targets.append(call('register', path=str(path))['target'])
        call('schedule_configure', plan=dict(interval_s=60, jitter_ms=0))
        enabled = request(endpoint, 'schedule_enable')
        if not args.p1_acceptance:
            assert not enabled['ok'] and 'P1 acceptance missing' in enabled['error'], enabled
            time.sleep(2)
            status = call('status')
            assert not status['sessions'] and not status['periodic_enabled'], status
            result = dict(gate_negative='PASS', periodic_runtime='BLOCKED', reason='no P1 admission')
        else:
            if not enabled['ok']: raise RuntimeError(enabled)
            duration = args.cycles*60+10
            begin = time.monotonic_ns()+200_000_000
            for i in range(2):
                log = (out/('workload-%d.log' % i)).open('x')
                logs.append(log)
                child = subprocess.Popen(['/session_launch', str(root/('root%d' % i)), str(i*2),
                                          '/workload', 'throughput', str(duration), str(begin)], stdout=log, stderr=log)
                children.append(child)
            end = time.monotonic()+duration+10
            complete = {}
            while time.monotonic() < end and len(complete) < args.cycles:
                status = call('status')
                if status['state'] == 'FAULTED': raise RuntimeError(status)
                for sid in status['sessions']:
                    record = call('status', session=sid)
                    if record.get('finalized'):
                        if record['result'] != 'COMPLETE' or not record.get('objects_absent'):
                            raise AssertionError(record)
                        complete[sid] = record
                time.sleep(.5)
            assert len(complete) == args.cycles, complete
            call('schedule_pause')
            schedule = call('schedule_status')
            assert all(value['valid_ns'] is not None for value in schedule['roots'].values()), schedule
            for child in children:
                assert child.wait(timeout=duration+10) == 0
            result = dict(periodic_functional='PASS', cycles=len(complete),
                          period_s=60, schedule=schedule, performance_acceptance='NOT_RUN')
        (out/'result.json').write_text(json.dumps(result, indent=2))
        print('CIS_PERIODIC_FUNCTION '+json.dumps(result), flush=True)
    finally:
        try:
            if daemon.poll() is None:
                request(endpoint, 'stop')
                daemon.wait(timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            if daemon.poll() is None: daemon.terminate()
        for child in children:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=10)
        for log in logs: log.close()
        controller_log.close()
        # Failed journals/cgroups are retained in this disposable VM for diagnosis.
        print('CIS_PERIODIC_EVIDENCE '+str(out), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--p1-acceptance')
    parser.add_argument('--cycles', type=int, default=3)
    run(parser.parse_args())
