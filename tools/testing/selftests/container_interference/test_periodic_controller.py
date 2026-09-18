# SPDX-License-Identifier: GPL-2.0
from concurrent.futures import ThreadPoolExecutor
import errno
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'container_interference'))
from process_budget import ProcessBudget
from schedule import Schedule
import session


class ControllerTests(unittest.TestCase):
    def test_identity_universe_is_not_target_set(self):
        roots = {str(i): dict(fd=i+10, id=i+1, generation=9) for i in range(256)}
        owner = session.worker_roots(roots, ['0'], 'owner')
        self.assertEqual(len(owner), 256)
        self.assertEqual(sum(r['session_target'] for r in owner.values()), 1)
        self.assertFalse(owner['1']['session_target'])
        self.assertNotIn('session_target', roots['1'])
        self.assertEqual(list(session.worker_roots(roots, ['0'], 'ip')), ['0'])
        self.assertEqual(session.worker_roots(roots, ['0'], 'fd'), owner)
        for targets in ([], ['0']*2, ['0','1','2'], ['missing']):
            with self.assertRaises(ValueError): session.worker_roots(roots, targets, 'owner')
        self.assertNotIn('owner_identities', session.compact_record(dict(owner_identities=owner)))

    def test_cancel_reply_omits_bounded_identity_universe(self):
        c = self.controller()
        c.history['7'] = dict(session_id='7', owner_identities={str(i): dict(id=i+1, generation=99,
                              session_target=i==0) for i in range(256)})
        response = c.request(dict(version=1, op='cancel', session='7'))
        self.assertNotIn('owner_identities', response)
        self.assertLess(len(session.encoded(response)), session.MAX_PACKET)
        self.assertEqual(len(c.history['7']['owner_identities']), 256)

    def test_schedule_validation(self):
        session.validate(dict(version=1, op='schedule_configure', plan={}))
        for offset in (-1, True, 257):
            with self.assertRaises(ValueError): session.validate(dict(version=1, op='schedule_status', offset=offset))

    def test_no_receipt_cannot_enable(self):
        controller = self.controller()
        controller.schedule = Schedule({}, lambda: 1)
        controller.args = type('Args', (), {'p1_acceptance': None})()
        with self.assertRaisesRegex(ValueError, 'P1 acceptance missing'):
            controller.request(dict(version=1, op='schedule_enable'))
        self.assertFalse(controller.schedule.enabled)

    def test_nonce_replay_rejected_before_lookup(self):
        controller = self.controller()
        controller.schedule = Schedule({}, lambda: 1)
        controller.nonce_epoch = 'a'*32
        with self.assertRaisesRegex(ValueError, 'epoch expired'):
            controller.start(dict(nonce='old', nonce_epoch='b'*32))

    def controller(self):
        c = object.__new__(session.Controller)
        c.io, c.active, c.schedule, c.admission = None, None, None, None
        c.faulted, c.stopping = False, False
        c.surveys, c.history, c.roots = {}, {}, {}
        c.references, c.boundary_reads = {}, 0
        c.survey_epoch=0
        c.manifest={}
        c.diagnoses=session.DiagnosisQueue(session.now)
        c.children = session.ChildProcesses()
        return c

    def test_slow_io_does_not_block_status(self):
        c = self.controller()
        c.nonce_epoch = 'a'*32
        c.executor = ThreadPoolExecutor(max_workers=1)
        c.wake_w = Mock()
        waiting, release = threading.Event(), threading.Event()
        def action():
            waiting.set()
            if not release.wait(2): raise TimeoutError('test timeout')
            return 7
        got = []
        try:
            c.submit_io('slow', action, got.append)
            self.assertTrue(waiting.wait(1))
            self.assertEqual(c.request(dict(version=1, op='status'))['state'], 'IDLE')
            with self.assertRaises(RuntimeError): c.submit_io('unbounded', action, got.append)
            release.set()
            c.io[1].result(timeout=1)
            c.pump_io()
            self.assertEqual(got, [7])
        finally:
            release.set()
            c.executor.shutdown()

    def test_verified_recovery_is_final_but_not_complete_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            c=self.controller();c.boot='one';c.faulted=True
            c.args=type('Args',(),{'residue':'/test/residue'})()
            c.global_journal=Path(directory)/'journal.json'
            pointer=dict(session_id='7',directory=directory,state='FAULTED')
            record=dict(session_id='7',boot_id='one',worker_pid=2147483647,
                        state='FAULTED',result=None,finalized=False,objects_absent=False,
                        inventory=dict(maps=[3],programs=[4]),
                        collector_bundle={'large_source_manifest':'x'*session.MAX_PACKET})
            c.global_journal.write_text(json.dumps(pointer))
            path=Path(directory)/'7.json';path.write_text(json.dumps(record))
            with patch('session.subprocess.run',return_value=Mock(returncode=1)):
                with self.assertRaisesRegex(OSError,'absent not proved'):
                    c.request(dict(version=1,op='recover'))
            self.assertEqual(json.loads(path.read_text()),record)
            with patch('session.subprocess.run',return_value=Mock(returncode=0)) as verifier:
                result=c.request(dict(version=1,op='recover'))
            self.assertEqual(verifier.call_args.args[0],['/test/residue','m:3','p:4'])
            self.assertTrue(result['objects_absent'] and result['finalized'])
            self.assertFalse(c.faulted)
            self.assertEqual(result['result'],'FAILED')
            saved=json.loads(path.read_text())
            self.assertEqual(session.compact_record(saved),result)
            self.assertEqual(saved['collector_bundle'],record['collector_bundle'])
            self.assertLess(len(session.encoded(dict(ok=True,data=result))),session.MAX_PACKET)
            self.assertGreater(result['recovery_checked_ns'],0)

    def test_inventory_not_armed_until_durable_callback(self):
        c = self.controller()
        c.active = dict(record=dict(session_id='1', state='ARMED', targets=[], window_ms=2000,
                                   cancellation_requested=False), arm_pending=True,
                        budget=ProcessBudget(0, 2000), channel=Mock())
        c.process_cpu = lambda: 0
        jobs = []
        c.persist = Mock()
        c.submit_io = lambda name, work, done: jobs.append((work, done))
        c.pump_io()
        c.active['channel'].send.assert_not_called()
        work, done = jobs.pop()
        result = work()
        c.persist.assert_called_once()
        c.active['channel'].send.assert_not_called()
        done(result)
        c.active['channel'].send.assert_called_once_with(b'ARM')

    def test_publication_keeps_admission_owned(self):
        c = self.controller()
        c.active = dict(record=dict(session_id='1', receipt=dict(result='COMPLETE'), cancellation_requested=False,
                                    collector='ip', targets=[], transitions=[]), killed=False,
                        controller_cpu_begin=time.process_time_ns(), child_cpu_begin=session.reaped_child_cpu_ns(),
                        process_cpu_begin=0, memory_peak=0, budget=ProcessBudget(0, 2000))
        c.process_cpu = lambda: 100
        jobs = []
        c.submit_io = lambda name, work, done: jobs.append((work, done))
        c.persist = Mock()
        c.release_active = Mock()
        c.finish_verified(dict(verified=True, after=None))
        self.assertEqual(c.active['record']['state'], 'VERIFY')
        self.assertTrue(c.active['publishing'])
        c.release_active.assert_not_called()
        work, done = jobs.pop()
        saved = work()
        self.assertTrue(saved['finalized'])
        c.release_active.assert_not_called()
        done(saved)
        c.release_active.assert_called_once()

    def test_late_budget_cannot_publish_success(self):
        c = self.controller()
        c.active = dict(record=dict(session_id='1', state='VERIFY', budget_reason='limit'),
                        killed=False, process_cpu_begin=0, budget=ProcessBudget(0, 2000))
        c.process_cpu = lambda: 100
        c.persist = Mock()
        c.release_active = Mock()
        jobs = []
        c.submit_io = lambda name, work, done: jobs.append((work, done))
        c.final_record(dict(session_id='1', state='IDLE', result='COMPLETE', finalized=True))
        c.release_active.assert_not_called()
        work, done = jobs.pop()
        done(work())
        self.assertEqual(c.active['record']['result'], 'PARTIAL')
        c.persist.assert_called_once()

    def test_history_preserves_old_evidence_and_faults(self):
        with tempfile.TemporaryDirectory() as directory:
            c = self.controller()
            c.directory = Path(directory)
            c.boot = 'boot'
            c.schedule = Schedule(dict(retain_seconds=60, retain_sessions=1), lambda: 1000*10**9)
            c.nonce_epoch = 'a'*32
            for i in range(3):
                sid = str(i)
                record = dict(session_id=sid, boot_id='boot', state='IDLE', stopped_ns=1,
                              retention_managed=True, objects_absent=True)
                c.history[sid] = record
                (c.directory/(sid+'.json')).write_text(json.dumps(record))
                (c.directory/(sid+'.jsonl')).write_text('owned')
            c.history['1']['retention_managed'] = False
            c.history['2']['state'] = 'FAULTED'
            saved_epochs = []
            c.save_metadata = lambda: saved_epochs.append(c.nonce_epoch)
            with patch.object(session, 'now', return_value=1000*10**9): c.retire_history()
            self.assertNotIn('0', c.history)
            self.assertTrue((c.directory/'1.jsonl').exists())
            self.assertTrue((c.directory/'2.jsonl').exists())
            self.assertNotEqual(saved_epochs, ['a'*32])

    def test_failed_epoch_commit_does_not_delete(self):
        with tempfile.TemporaryDirectory() as directory:
            c = self.controller()
            c.directory, c.boot = Path(directory), 'boot'
            c.schedule = Schedule(dict(retain_seconds=60, retain_sessions=1), lambda: 1000*10**9)
            c.nonce_epoch = 'a'*32
            for i in range(2):
                c.history[str(i)] = dict(session_id=str(i), boot_id='boot', state='IDLE', stopped_ns=1,
                                        retention_managed=True, objects_absent=True)
                (c.directory/(str(i)+'.json')).write_text('{}')
            c.save_metadata = Mock(side_effect=OSError('disk full'))
            with patch.object(session, 'now', return_value=1000*10**9):
                with self.assertRaises(OSError): c.retire_history()
            self.assertEqual(len(list(c.directory.iterdir())), 2)

    def test_missing_acceptance_does_not_call_sampler(self):
        c = self.controller()
        c.schedule = Schedule({}, lambda: 1)
        c.args = Mock(p1_acceptance=None)
        c.start = Mock()
        with self.assertRaises(ValueError): c.request(dict(version=1, op='schedule_enable'))
        c.periodic_tick()
        c.start.assert_not_called()

    def test_worker_drain_closes_capture_before_helper_work(self):
        c = self.controller()
        budget = ProcessBudget(0, 2000)
        budget.check(100_000_000, 'CAPTURING')
        c.active = dict(record=dict(session_id='1', state='CAPTURING', transitions=[]),
                        budget=budget, channel=Mock())
        c.active['channel'].recv.return_value = b'{"state":"DRAIN"}'
        c.process_cpu = lambda: 135_000_000
        c.cancel = Mock()
        c.worker_event()
        self.assertEqual(budget.phase, 'DRAIN')
        self.assertIsNone(budget.check(150_000_000, 'VERIFY'))
        self.assertEqual(budget.snapshot()['phase_peak_cpu_ns']['CAPTURING'], 35_000_000)
        self.assertEqual(budget.snapshot()['phase_peak_cpu_ns']['DRAIN'], 15_000_000)
        c.cancel.assert_not_called()

    def test_pending_admission_can_cancel_without_worker(self):
        c = self.controller()
        c.nonce_epoch = 'a'*32
        record = dict(session_id='1', state='PREPARE', cancellation_requested=False)
        c.history['1'] = record
        c.admission = dict(record=record, request={}, roots=[], timed_out=False)
        self.assertEqual(c.request(dict(version=1, op='status'))['state'], 'PREPARE')
        c.request(dict(version=1, op='cancel', session='1'))
        c.children.spawn = Mock()
        jobs = []
        c.submit_io = lambda name, work, done: jobs.append((work, done))
        c.persist = Mock()
        fds = [os.open(os.devnull, os.O_WRONLY) for _ in range(2)]
        c.spawn_admitted(fds)
        c.children.spawn.assert_not_called()
        self.assertEqual(record['result'], 'CANCELLED')
        self.assertTrue(record['worker_never_spawned'])
        self.assertIsNotNone(c.admission)
        self.assertFalse(record['finalized'])
        self.assertEqual(record['state'], 'VERIFY')
        for fd in fds:
            with self.assertRaises(OSError): os.fstat(fd)
        work, done = jobs.pop()
        saved = work()
        self.assertFalse(record['finalized'])
        self.assertIsNotNone(c.admission)
        self.assertTrue(saved['finalized'])
        done(saved)
        self.assertIsNone(c.admission)
        self.assertTrue(record['finalized'])
        self.assertEqual(record['state'], 'IDLE')

    def test_start_queues_file_creation_before_spawning(self):
        c = self.controller()
        c.args = Mock(test_faults=False)
        c.survey_epoch = 0
        c.manifest = {key: 'test' for key in ('controller_sha256', 'worker_sha256',
            'residue_sha256', 'bpf_sha256', 'support_sha256', 'kernel_release', 'kernel_notes_sha256', 'kernel_cmdline_sha256')}
        c.roots['1:2'] = dict(fd=123, path='/sys/fs/cgroup/target', id=1, generation=2)
        c.retire_history = c.storage_admit = Mock()
        c.persist = Mock()
        c.children.spawn = Mock()
        jobs = []
        c.submit_io = lambda name, work, done: jobs.append((name, work, done))
        with patch.object(session.os, 'readlink', return_value='/sys/fs/cgroup/target'):
            result = c.start(dict(nonce='start', collector='ip', targets=['1:2']))
        self.assertEqual(result['state'], 'PREPARE')
        self.assertIs(c.admission['record'], result)
        c.persist.assert_not_called()
        c.children.spawn.assert_not_called()
        self.assertEqual(jobs[0][0], 'admission_files')
        with self.assertRaises(OSError):
            c.start(dict(nonce='second', collector='ip', targets=['1:2']))

    def test_pending_admission_rejects_mutation(self):
        c = self.controller()
        c.admission = dict(record={})
        for request in (dict(op='register', path='/sys/fs/cgroup/x'),
                        dict(op='unregister', target='1:2'),
                        dict(op='schedule_configure', plan={}), dict(op='survey_epoch'), dict(op='recover')):
            with self.assertRaises(OSError): c.request(dict(version=1, **request))

    def test_second_output_failure_closes_first_fd(self):
        c = self.controller()
        c.directory = Path('/not-accessed')
        c.persist = Mock()
        real_fd = os.open(os.devnull, os.O_WRONLY)
        with patch.object(session.os, 'open', side_effect=[real_fd, OSError(errno.ENOSPC, 'full')]):
            with self.assertRaises(OSError): c.prepare_files(dict(session_id='1'))
        with self.assertRaises(OSError): os.fstat(real_fd)

    def test_admission_io_failure_is_not_success(self):
        c = self.controller()
        c.executor = ThreadPoolExecutor(max_workers=1)
        c.wake_w = Mock()
        record = dict(session_id='1')
        c.admission = dict(record=record)
        c.children.spawn = Mock()
        try:
            c.submit_io('admission_files', lambda: c.prepare_files(record, 'admission_full'), c.spawn_admitted)
            with self.assertRaises(OSError): c.io[1].result(timeout=1)
            c.pump_io()
            self.assertTrue(c.faulted)
            self.assertEqual(record['result'], 'FAILED')
            self.assertFalse(record['durable_result'])
            self.assertIsNone(c.admission)
            c.children.spawn.assert_not_called()
        finally:
            c.executor.shutdown()

    def test_stop_while_admission_is_pending(self):
        c = self.controller()
        record = dict(session_id='1', cancellation_requested=False)
        c.history['1'] = record
        c.admission = dict(record=record)
        c.request(dict(version=1, op='stop'))
        self.assertTrue(c.stopping)
        self.assertTrue(record['cancellation_requested'])

    def test_failed_spawn_closes_socket_and_files(self):
        c = self.controller()
        c.args = Mock(worker='/does-not-exist', bpf='/none')
        record = dict(session_id='1', window_ms=2000, cancellation_requested=False)
        c.admission = dict(record=record, request=dict(collector='ip'), roots=[], timed_out=False)
        c.children.spawn = Mock(side_effect=OSError(errno.ENOENT, 'worker'))
        fds = [os.open(os.devnull, os.O_WRONLY) for _ in range(2)]
        with self.assertRaises(OSError): c.spawn_admitted(fds)
        self.assertTrue(c.faulted)
        for fd in fds:
            with self.assertRaises(OSError): os.fstat(fd)


if __name__ == '__main__': unittest.main()
