# SPDX-License-Identifier: GPL-2.0
from concurrent.futures import ThreadPoolExecutor
import json
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
        c.io, c.active, c.schedule = None, None, None
        c.faulted, c.stopping = False, False
        c.surveys, c.history, c.roots = {}, {}, {}
        c.references, c.boundary_reads = {}, 0
        c.helper_lock = threading.Lock()
        c.helpers = set()
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
                        process_cpu_begin=0, memory_peak=0)
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
                        killed=False, process_cpu_begin=0)
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


if __name__ == '__main__': unittest.main()
