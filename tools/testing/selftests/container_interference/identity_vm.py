#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Registered ancestry and migration under a real single-shot IP session."""
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time


def run():
    if not Path('/cis-disposable-vm').exists() or os.geteuid() or os.uname().machine != 'aarch64':
        raise RuntimeError('isolated ARM64 VM required')
    out = Path('/tmp/session-evidence')
    endpoint = '/run/cis-identity.sock'
    base = Path('/sys/fs/cgroup/cis-identity')
    base.mkdir()
    (base/'management').mkdir()
    (base/'management/cgroup.procs').write_text(str(os.getpid()))
    os.sched_setaffinity(0, {7})
    (base/'cgroup.subtree_control').write_text('+cpu +memory +cpuset')
    a, b = base/'a', base/'b'
    a.mkdir(); b.mkdir()
    records = out/'identity-records'
    controller_log = (out/'identity-controller.log').open('x')
    daemon = subprocess.Popen(['/usr/bin/python3', '/profile/session.py', '--socket', endpoint,
               '--directory', str(records), '--worker', '/profile/session-worker',
               '--bpf', '/profile/cis.bpf.o', '--residue', '/profile/session-residue', 'daemon'],
               stdout=controller_log, stderr=controller_log)
    child = None
    log = None

    def call(op, **fields):
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as channel:
            channel.settimeout(2)
            channel.connect(endpoint)
            channel.send(json.dumps(dict(version=1, op=op, **fields)).encode())
            result = json.loads(channel.recv(8192))
            if not result['ok']: raise RuntimeError(result['error'])
            return result['data']

    try:
        for _ in range(500):
            if Path(endpoint).exists(): break
            if daemon.poll() is not None: raise RuntimeError('controller died')
            time.sleep(.01)
        ta, tb = [call('register', path=str(root))['target'] for root in (a, b)]
        leaf = a/'dynamic-child'
        leaf.mkdir()
        try:
            call('register', path=str(leaf))
            raise AssertionError('overlapping registration accepted')
        except RuntimeError as error:
            assert 'overlap' in str(error)
        sid = call('start', collector='ip', nonce='migration', targets=[ta, tb], window_ms=2000)['session_id']
        for _ in range(1000):
            record = call('status', session=sid)
            if 'window' in record: break
            if record.get('finalized'): raise AssertionError(record)
            time.sleep(.005)
        start = record['window']['start_ns']
        log = (out/'identity-business.log').open('x')
        child = subprocess.Popen(['/session_launch', str(leaf), '0', '/workload', 'throughput', '3', str(start)],
                                 stdout=log, stderr=log)
        while time.monotonic_ns() < start+700_000_000: time.sleep(.005)
        moved_begin = time.monotonic_ns()
        pids = (leaf/'cgroup.procs').read_text().split()
        assert pids, 'no business tasks to migrate'
        for pid in pids: (b/'cgroup.procs').write_text(pid)
        moved_end = time.monotonic_ns()
        assert child.wait(timeout=10) == 0
        log.close(); log = None
        for _ in range(500):
            record = call('status', session=sid)
            if record.get('finalized'): break
            time.sleep(.01)
        assert record['result'] == 'COMPLETE' and record['objects_absent'], record
        counts = dict(before_a=0, after_b=0, ambiguous_boundary=0)
        for line in (records/(sid+'.jsonl')).read_text().splitlines():
            event = json.loads(line)
            if event.get('kind') != 'IP': continue
            fields = dict(re.findall(r'(\w+)=([^\s]+)', event['detail']))
            stamp = int(fields['sample_time_ns'])
            identity = '%s:%s' % (event['id'], event['generation'])
            if stamp < moved_begin-1_000_000:
                assert identity == ta, event
                counts['before_a'] += 1
            elif stamp > moved_end+1_000_000:
                assert identity == tb, event
                counts['after_b'] += 1
            else:
                counts['ambiguous_boundary'] += 1
        assert counts['before_a'] >= 16 and counts['after_b'] >= 16, counts
        leaf.rmdir(); a.rmdir(); a.mkdir()
        try:
            call('start', collector='ip', nonce='deletedRoot', targets=[ta])
            raise AssertionError('deleted root accepted')
        except RuntimeError as error:
            assert 'deleted or renamed' in str(error)
        call('unregister', target=ta)
        new = call('register', path=str(a))['target']
        assert new != ta
        report = dict(dynamic_descendant=True, overlap_rejected=True, migration=counts,
                      moved_begin_ns=moved_begin, moved_end_ns=moved_end,
                      deleted_registration_rejected=True, recreated_registration=new, previous_registration=ta,
                      limits='one controlled migration; boundary samples retained as ambiguous; not universal identity proof')
        (out/'identity-result.json').write_text(json.dumps(report))
        print('CIS_PROFILE_IDENTITY '+json.dumps(report), flush=True)
    finally:
        if child is not None and child.poll() is None:
            child.terminate(); child.wait(timeout=10)
        if daemon.poll() is None:
            call('stop'); daemon.wait(timeout=10)
        if log is not None: log.close()
        controller_log.close()


if __name__ == '__main__': run()
