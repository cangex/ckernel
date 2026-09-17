# SPDX-License-Identifier: GPL-2.0
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import subprocess
import sys
import threading
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'container_interference'))
import child_usage


class ChildUsageTests(unittest.TestCase):
    def test_live_clock_uses_nanoseconds_and_process_scope(self):
        with patch.object(child_usage.time, 'clock_gettime_ns', return_value=123456789) as clock:
            self.assertEqual(child_usage.live_cpu_ns(42), 123456789)
            clock.assert_called_once_with((~42 << 3) | 2)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux process CPU clock ABI')
    def test_linux_live_clock_matches_self_process_clock(self):
        before = child_usage.time.process_time_ns()
        measured = child_usage.live_cpu_ns(os.getpid())
        after = child_usage.time.process_time_ns()
        self.assertLessEqual(before, measured)
        self.assertLessEqual(measured, after)

    def test_exit_during_poll_counted_once(self):
        registry = child_usage.ChildProcesses()
        state = dict(reaped=7)
        child = Mock(pid=42)
        def reap():
            state['reaped'] = 107
            return 0
        child.poll.side_effect = reap
        registry.children[42] = child
        with patch.object(child_usage.time, 'process_time_ns', return_value=3), \
                patch.object(child_usage, 'reaped_cpu_ns', side_effect=lambda: state['reaped']), \
                patch.object(child_usage, 'live_cpu_ns') as live:
            self.assertEqual(registry.cpu_ns(), 110)
            self.assertEqual(registry.cpu_ns(), 110)
            live.assert_not_called()
        self.assertEqual(registry.pids(), [])

    def test_alive_to_reaped_conserves_cpu(self):
        registry = child_usage.ChildProcesses()
        state = dict(reaped=7, done=False)
        child = Mock(pid=42)
        def reap():
            if state['done']:
                state['reaped'] = 107
                return 0
            return None
        child.poll.side_effect = reap
        registry.children[42] = child
        with patch.object(child_usage.time, 'process_time_ns', return_value=3), \
                patch.object(child_usage, 'reaped_cpu_ns', side_effect=lambda: state['reaped']), \
                patch.object(child_usage, 'live_cpu_ns', return_value=100):
            self.assertEqual(registry.cpu_ns(), 110)
            state['done'] = True
            self.assertEqual(registry.cpu_ns(), 110)

    def test_reaping_cannot_interleave_with_live_snapshot(self):
        registry = child_usage.ChildProcesses()
        reading, resume, trying_reap = threading.Event(), threading.Event(), threading.Event()
        state = dict(done=False, reaped=7)
        child = Mock(pid=42)
        def poll():
            if state['done']:
                state['reaped'] = 107
                return 0
            return None
        def live(_):
            reading.set()
            if not resume.wait(2):
                raise TimeoutError('test did not release snapshot')
            return 100
        def reap():
            trying_reap.set()
            return registry.poll(child)
        child.poll.side_effect = poll
        registry.children[42] = child
        with patch.object(child_usage.time, 'process_time_ns', return_value=3), \
                patch.object(child_usage, 'reaped_cpu_ns', side_effect=lambda: state['reaped']), \
                patch.object(child_usage, 'live_cpu_ns', side_effect=live), ThreadPoolExecutor(2) as executor:
            snapshot = executor.submit(registry.cpu_ns)
            try:
                self.assertTrue(reading.wait(1))
                state['done'] = True
                reaper = executor.submit(reap)
                self.assertTrue(trying_reap.wait(1))
                self.assertFalse(reaper.done())
                self.assertEqual(state['reaped'], 7)
            finally:
                resume.set()
            self.assertEqual(snapshot.result(timeout=1), 110)
            self.assertEqual(reaper.result(timeout=1), 0)
            self.assertEqual(registry.cpu_ns(), 110)

    def test_failed_spawn_does_not_register(self):
        registry = child_usage.ChildProcesses()
        with patch.object(child_usage.subprocess, 'Popen', side_effect=OSError('spawn failed')):
            with self.assertRaises(OSError):
                registry.spawn(['test'])
        self.assertEqual(registry.pids(), [])

    def test_wait_does_not_hold_snapshot_lock(self):
        registry = child_usage.ChildProcesses()
        child = Mock(pid=42, args=['test'])
        child.poll.return_value = None
        registry.children[42] = child
        with self.assertRaises(subprocess.TimeoutExpired):
            registry.wait(child, timeout=0)
        self.assertEqual(registry.pids(), [42])
        child.poll.return_value = 0
        self.assertEqual(registry.wait(child), 0)
        self.assertEqual(registry.pids(), [])

    def test_live_counter_failure_is_not_silently_zero(self):
        registry = child_usage.ChildProcesses()
        child = Mock(pid=42)
        child.poll.return_value = None
        registry.children[42] = child
        with patch.object(child_usage, 'live_cpu_ns', side_effect=FileNotFoundError('lost child')):
            with self.assertRaises(FileNotFoundError):
                registry.cpu_ns()

    def test_real_child_exit_reaped_and_registry_released(self):
        registry = child_usage.ChildProcesses()
        child = registry.spawn([sys.executable, '-c', 'pass'])
        self.assertEqual(registry.wait(child, timeout=5), 0)
        self.assertEqual(registry.pids(), [])
        self.assertGreaterEqual(registry.cpu_ns(), 0)


if __name__ == '__main__': unittest.main()
