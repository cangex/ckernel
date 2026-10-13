import unittest
import json
import tempfile
import time
from pathlib import Path
from unittest.mock import patch
from go_fs_matrix import BarrierClock, geometry, plan, cpu_stat, TOTAL_INODES, Window
from fs_domain_plan import COUNTS, layout, placement

class MatrixTest(unittest.TestCase):
    def test_formal_complete_and_counterbalanced(self):
        p = plan('formal')
        self.assertEqual(len(p), 64)
        self.assertEqual(len({v['name'] for v in p}), 64)
        for d in COUNTS:
            for n in (1, 24):
                self.assertEqual(sum(v['domains'] == d and v['n'] == n for v in p), 8)
            orders = [[v['domains'] for v in p if v['block'] == b][::2] for b in range(8)]
            for pos in range(4):
                self.assertEqual(sum(o[pos] == d for o in orders), 2)

    def test_pilot_separate(self):
        p = plan('pilot')
        self.assertEqual(len(p), 24)
        self.assertFalse({v['name'] for v in p} & {v['name'] for v in plan('formal')})

    def test_placement_every_state(self):
        for row in plan('formal'):
            d, r = row['domains'], row['rotation']
            groups = [placement(s, d, r) for s in range(24)]
            self.assertTrue(all(groups.count(g) == 24 // d for g in range(d)))

    def test_one_callback_and_common_barrier(self):
        values = []
        c = BarrierClock(values.append)
        with patch('go_fs_matrix.time.monotonic_ns', return_value=123):
            self.assertEqual(c.monotonic_ns(), 123)
        self.assertEqual(values, [2_000_000_123])
        with self.assertRaises(RuntimeError):
            c.monotonic_ns()

    def test_geometry_all_arms(self):
        for d in COUNTS:
            rows = []
            for s in layout(d, total_inodes=TOTAL_INODES):
                rows.append(dict(spec=s, uuid=str(s['index']), capacity={}, superblock=(
                    f'Block count: {s["bytes"] // 4096}\nBlock size: 4096\n'
                    f'Inode count: {s["inodes"]}\nTotal journal blocks: {s["journal_mib"] * 256}\n'
                    'Filesystem features: has_journal extent 64bit\n')))
            self.assertEqual(len(geometry(rows)), d)
            rows[0]['superblock'] = rows[0]['superblock'].replace('Block size: 4096', 'Block size: 1024')
            with self.assertRaises(AssertionError):
                geometry(rows)

    def test_cpu_parser(self):
        self.assertEqual(cpu_stat('usage_usec 42\nuser_usec 21\nsystem_usec 21\n')['usage_usec'], 42)

    def test_window_stops_on_existing_action_not_late_done_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)
            (p / 'memory.current').write_text('42')
            action = p / 'actions.json'
            final = dict(kind='execute_bash', id=13, source_command='go version', executed_command='go version',
                         exit_code=0, expected_exit_code=0, end_ns=123, output='go version go1.17 linux/arm64')
            action.write_text(json.dumps([dict(exit_code=0, end_ns=122)] * 5 + [final], indent=2))
            w = Window({0: p}, [], {0: action})
            with patch('go_fs_matrix.snapshot', return_value={'cgroups': {'0': {'memory.current': '42'}}}), patch('go_fs_matrix.ActionWatch'):
                w.start(time.monotonic_ns())
                w.thread.join(1)
                self.assertFalse(w.thread.is_alive())
                self.assertIsNone(w.error)
                self.assertEqual(w.completed_actions, {0: 123})
                self.assertFalse((p / 'done.json').exists())

    def test_incomplete_actions_not_accepted_on_stop(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)
            (p / 'memory.current').write_text('42')
            action = p / 'actions.json'
            action.write_text(json.dumps([dict(exit_code=0, end_ns=123)] * 5))
            w = Window({0: p}, [], {0: action})
            with patch('go_fs_matrix.snapshot', return_value={'cgroups': {'0': {'memory.current': '42'}}}), patch('go_fs_matrix.ActionWatch') as watch:
                watch.return_value.poll.return_value = set()
                w.start(time.monotonic_ns())
                self.assertTrue(w.ready.wait(1))
                with self.assertRaises(RuntimeError):
                    w.finish()

if __name__ == '__main__':
    unittest.main()
