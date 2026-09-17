# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'container_interference'))
from recursion_report import snapshot


class RecursionReport(unittest.TestCase):
    def raw(self):
        return ('version=1 enabled=1 trace_active=0 bytes_per_possible_cpu=800 snapshot=non_atomic\n'
                'cpu=0 skipped=2 sync=1 irq=1\n'
                'phase cpu=0 kind=1 phase=3 count=2\n'
                'sample cpu=0 count=2 object=abcd outer=0123 caller=def0 kind=1 phase=3 outer_kind=2 outer_phase=4 preempt=100\n')

    def test_quiescent(self):
        value = snapshot(self.raw())
        self.assertEqual(value['skipped'], 2)
        self.assertEqual(value['samples'][0]['caller'], 0xdef0)

    def test_gate_counts_do_not_replace_skipped_counts(self):
        value = snapshot(self.raw().replace('version=1', 'version=2').replace(
            'snapshot=non_atomic', 'snapshot=non_atomic wait_gate=1 gate_bytes=8192').replace(
            'sync=1 irq=1', 'sync=1 irq=1 filtered=10000'))
        self.assertTrue(value['gate_enabled'])
        self.assertEqual(value['skipped'], 2)
        self.assertEqual(value['gate_filtered'], 10000)

    def test_running_and_disabled_rejected(self):
        for old, new in [('trace_active=0', 'trace_active=1'), ('enabled=1', 'enabled=0')]:
            with self.assertRaises(ValueError):
                snapshot(self.raw().replace(old, new))

    def test_counter_inconsistency_rejected(self):
        with self.assertRaises(ValueError):
            snapshot(self.raw().replace('count=2\n', 'count=1\n'))
