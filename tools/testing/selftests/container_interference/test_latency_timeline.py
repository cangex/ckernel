# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'container_interference'))
from latency_timeline import analyze


class Timeline(unittest.TestCase):
    text = ('CIS_LATENCY_TIMELINE count=2 post_window_export=1 clock=guest_monotonic\n'
            'CIS_LATENCY_SAMPLE index=0 due_ns=1000 begin_ns=1050 finish_ns=1060\n'
            'CIS_LATENCY_SAMPLE index=1 due_ns=501000 begin_ns=501090 finish_ns=501100\n'
            'CIS_LATENCY count=2 p99_ns=100 max_ns=100 rate=2000 start_ns=1000 end_ns=501100\n')

    def test_components_and_scope(self):
        result = analyze(self.text)
        self.assertEqual(result['tail_wait_mean_ns'], 90)
        self.assertEqual(result['tail_execution_mean_ns'], 10)
        self.assertIsNone(result['host_clock_alignment'])
        self.assertFalse(result['phase_complete'])

    def test_duplicate_not_a_complete_timeline(self):
        with self.assertRaises(ValueError): analyze(self.text.replace('index=1', 'index=0'))

    def test_summary_mismatch(self):
        with self.assertRaises(ValueError): analyze(self.text.replace('p99_ns=100', 'p99_ns=101'))

    def test_clock_backwards(self):
        with self.assertRaises(ValueError): analyze(self.text.replace('begin_ns=1050', 'begin_ns=999'))

    def test_no_trace_is_not_pass(self):
        with self.assertRaises(ValueError): analyze('CIS_LATENCY count=2\n')
