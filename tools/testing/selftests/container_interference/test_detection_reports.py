#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]/'container_interference'))
from detection_latency import gate
from detection_report import analyze


def truth():
    return {'version': 1, 'clock': 'CLOCK_MONOTONIC', 'independent_truth': True, 'run_id': 'unit-only',
            'episodes': [{'episode_id': 'a', 'id': 1, 'generation': 2, 'start_ns': 1000000000,
                          'end_ns': 2000000000, 'positive': True, 'free_slot': True,
                          'supported': True, 'strength_qualified': True}]}


def event(kind='FAST_ALERT', time=1100000000, generation=2, **extra):
    return dict(kind=kind, time_ns=time, id=1, generation=generation, **extra)


class DetectionReports(unittest.TestCase):
    def test_small_sample_cannot_certify_p99(self):
        self.assertEqual(gate([1]*10, 500, .99)['status'], 'UNRESOLVED')
        self.assertEqual(gate([1]*299, 500, .99)['status'], 'PASS')

    def test_missing_episode_not_filtered(self):
        r = analyze(truth(), [])
        self.assertEqual(r['gates']['warning_p99']['episodes'], 1)
        self.assertEqual(r['gates']['warning_p99']['misses'], 1)
        self.assertEqual(r['unserved_eligible_episodes'], 1)
        self.assertFalse(r['latency_gate_pass'])

    def test_generation_and_old_alert_do_not_match(self):
        r = analyze(truth(), [event(generation=1), event(time=999999999)])
        self.assertEqual(r['eligible_warning_recall'], 0)

    def test_queue_and_attach_time_not_detector_time(self):
        r = analyze(truth(), [event(), event('diagnostic_start', 1300000001, detail='ready_ns=1300000000')])
        self.assertEqual(r['episodes'][0]['warning_delay_ns'], 100000000)
        self.assertEqual(r['episodes'][0]['candidate_to_ready_ns'], 200000000)

    def test_raw_owner_not_completed_relation(self):
        r = analyze(truth(), [event('OWNER')])
        self.assertIsNone(r['episodes'][0]['first_relation_ns'])

    def test_wrong_negative_relation_blocks(self):
        t = truth(); t['episodes'][0]['positive'] = False
        r = analyze(t, [event('relation', protocol_version=2, relation_type='holder_waiter',
                             level='E2', causal=False, validated=True)])
        self.assertEqual(r['wrong_holder_relations'], 1)
        self.assertFalse(r['latency_gate_pass'])

    def test_ambiguous_overlap_rejected(self):
        t = truth(); t['episodes'].append(dict(t['episodes'][0], episode_id='b'))
        with self.assertRaises(ValueError): analyze(t, [])

    def test_disabled_capture_not_low_latency_pass(self):
        r = analyze(truth(), [event(), event('budget_disable')])
        self.assertEqual(len(r['quality_failures']), 1)
        self.assertFalse(r['latency_gate_pass'])


if __name__ == '__main__': unittest.main()
