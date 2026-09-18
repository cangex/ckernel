#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""X0 real controller/worker lifecycle in an exclusive disposable VM.

No altered clock or shortened permit is accepted as expiry evidence. Use
--expiry for a separate full twenty-minute expiry case.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time
from types import SimpleNamespace

import collector_manifest
import prototype_admission as admission
from session import source_manifest


def run(expiry=False, fault=False):
    os.umask(0o077)
    env = admission.environment(); admission.check_environment(env)
    os.sched_setaffinity(0, {7})
    out = Path('/tmp/prototype-evidence'); out.mkdir(mode=0o700)
    roots = Path('/sys/fs/cgroup/cis-x0'); roots.mkdir()
    (roots/'management').mkdir(); (roots/'management/cgroup.procs').write_text(str(os.getpid()))
    (roots/'cgroup.subtree_control').write_text('+cpu +memory +cpuset')
    for i in range(2): (roots/('root%d' % i)).mkdir()
    args = SimpleNamespace(worker='/profile/session-worker', residue='/profile/session-residue', bpf='/profile/cis.bpf.o')
    if fault:
        # A deliberately failing verifier cannot certify absent kernel objects.
        # The real verifier is used independently before the guest shuts down.
        helper = out/'failing-residue'; helper.write_text('#!/bin/sh\nexit 1\n'); helper.chmod(0o700)
        args.residue = str(helper)
    source = source_manifest(args, env['boot_id'])
    permit = admission.create(source, env, time.monotonic_ns())
    (out/'permit.json').write_text(json.dumps(permit, indent=2))
    (out/'plan.json').write_text(json.dumps(dict(schema='cis-x0-plan-v1', expiry=expiry, fault=fault,
        interval_s=60, no_fake_clock=True, source=source), indent=2))
    endpoint = '/run/cis-x0.sock'
    command = ['/usr/bin/python3', '/profile/session.py', '--socket', endpoint,
               '--directory', str(out/'records'), '--worker', args.worker, '--residue', args.residue,
               '--bpf', args.bpf, '--admission-policy', 'prototype', '--prototype-permit', str(out/'permit.json'), 'daemon']
    log = (out/'controller.log').open('x'); audit = (out/'requests.jsonl').open('x')
    daemon = None; checks = []; children = []; sequence = 0

    def request(op, rejected=False, **fields):
        nonlocal sequence
        message = dict(version=1, op=op, **fields); before = time.monotonic_ns()
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as sock:
            sock.settimeout(15); sock.connect(endpoint); sock.send(json.dumps(message).encode())
            reply = json.loads(sock.recv(8192))
        sequence += 1
        audit.write(json.dumps(dict(sequence=sequence, before_ns=before, after_ns=time.monotonic_ns(), request=message, response=reply))+'\n'); audit.flush()
        assert reply['ok'] is not rejected, reply
        return reply if rejected else reply['data']

    def start_daemon():
        child = subprocess.Popen(command, stdout=log, stderr=log)
        limit = time.monotonic()+10
        while time.monotonic()<limit:
            assert child.poll() is None, 'controller exited'
            try:
                request('status'); return child
            except (FileNotFoundError, ConnectionRefusedError): time.sleep(.05)
        raise TimeoutError('controller readiness')

    def stop_daemon():
        request('stop'); assert daemon.wait(timeout=20) == 0

    def finish(sid, expected='IDLE'):
        limit = time.monotonic()+25
        while time.monotonic()<limit:
            row = request('status', session=sid)
            if row.get('finalized'):
                assert row['state'] == expected, row
                full = json.loads((out/'records'/(sid+'.json')).read_text())
                if expected == 'IDLE': assert full['objects_absent'] is True, full
                return full
            time.sleep(.1)
        raise TimeoutError('terminal session')

    def add_targets():
        return [request('register', path=str(roots/('root%d'%i)))['target'] for i in range(2)]

    def note(name, **data):
        checks.append(dict(name=name, status='PASS', time_ns=time.monotonic_ns(), **data))
        (out/'checks.json').write_text(json.dumps(checks, indent=2))

    try:
        daemon = start_daemon(); targets = add_targets()
        if expiry:
            request('schedule_configure', plan=dict(interval_s=60, jitter_ms=0))
            epoch = request('status')['nonce_epoch']
            # Keep paused: expiry is tested without consuming any collection slots.
            time.sleep(max(0, (permit['expires_ns']-time.monotonic_ns())/1e9)+.1)
            request('schedule_enable', rejected=True)
            request('start', rejected=True, collector='ip', targets=targets, nonce='expired', nonce_epoch=epoch)
            status = request('status'); assert not status['prototype_sessions_started']
            note('real_permit_expiry', expires_ns=permit['expires_ns'])
        elif fault:
            sid = request('start', collector='ip', targets=targets, nonce='failedcleanup')['session_id']
            row = finish(sid, 'FAULTED')
            request('start', rejected=True, collector='ip', targets=targets, nonce='afterfault')
            inv = row['inventory']
            subprocess.run(['/profile/session-residue'] + ['m:%d'%x for x in inv['maps']] +
                           ['p:%d'%x for x in inv['programs']], check=True)
            note('failed_verification_blocks_admission', session=sid,
                 real_verifier_absent=True, injected_verifier_failed=True)
        else:
            for name in collector_manifest.COLLECTORS:
                sid = request('start', collector=name, targets=targets, nonce='load'+name)['session_id']
                row = finish(sid)
                assert row['result'] == 'COMPLETE', row
                collector_manifest.validate_inventory(name, row['inventory'])
                note('selective_load_'+name, session=sid)
            old_epoch = request('schedule_configure', plan=dict(interval_s=60,jitter_ms=0))['nonce_epoch']
            enabled = request('schedule_enable')
            sid = request('start', collector='ip', targets=targets, nonce='manual', nonce_epoch=old_epoch)['session_id']
            request('schedule_pause')
            request('unregister', rejected=True, target=targets[0])
            finish(sid)
            request('start', rejected=True, collector='ip', targets=targets, nonce='tooearly', nonce_epoch=old_epoch)
            status = request('schedule_status'); assert not status['enabled']
            assert status['skipped']['manual_consumed_slot'] == 1
            note('pause_drain_and_shared_manual_budget', session=sid)
            ledger = request('status')['prototype_sessions_started']
            stop_daemon(); daemon = start_daemon()
            state = request('status'); scheduled = request('schedule_status')
            assert not scheduled['enabled'] and not scheduled['roots']
            assert state['nonce_epoch'] != old_epoch and state['prototype_sessions_started'] == ledger
            targets = add_targets()
            request('start', rejected=True, collector='ip', targets=targets, nonce='oldnonce', nonce_epoch=old_epoch)
            request('start', rejected=True, collector='ip', targets=targets, nonce='restartbudget', nonce_epoch=state['nonce_epoch'])
            note('restart_paused_nonce_and_budget_preserved')
            request('unregister', target=targets[1]); assert targets[1] not in request('schedule_status')['roots']
            note('unregister_removes_future_target')
            targets = targets[:1]
            # Miss two real service slots. On resume, only one slot may be served.
            request('schedule_enable')
            before_count = request('status')['prototype_sessions_started']
            os.kill(daemon.pid, signal.SIGSTOP)
            try: time.sleep(125)
            finally: os.kill(daemon.pid, signal.SIGCONT)
            limit = time.monotonic()+20
            while time.monotonic()<limit:
                state = request('status')
                if state['prototype_sessions_started'] > before_count and state['state'] == 'IDLE': break
                time.sleep(.1)
            state = request('status'); schedule = request('schedule_status')
            assert state['prototype_sessions_started'] == before_count+1, state
            assert schedule['skipped'].get('missed_slots', 0) >= 1, schedule
            assert schedule['next_ns'] > time.monotonic_ns()+40*10**9
            request('schedule_pause'); time.sleep(3)
            assert request('status')['prototype_sessions_started'] == before_count+1
            note('real_missed_slots_not_replayed')
        result = dict(schema='cis-x0-result-v1', status='PASS', checks=checks, source=source,
                      performance_certification='NOT_ACCEPTED', expiry_test=expiry, failed_cleanup_test=fault)
        (out/'result.json').write_text(json.dumps(result, indent=2))
        print('CIS_X0_RESULT '+json.dumps(result), flush=True)
    finally:
        if daemon and daemon.poll() is None:
            try: stop_daemon()
            except Exception:
                daemon.terminate()
                try: daemon.wait(timeout=10)
                except subprocess.TimeoutExpired: daemon.kill(); daemon.wait()
        audit.close(); log.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); group = parser.add_mutually_exclusive_group()
    group.add_argument('--expiry', action='store_true'); group.add_argument('--fault', action='store_true')
    args = parser.parse_args(); run(args.expiry, args.fault)
