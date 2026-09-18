# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'container_interference'))
from session_quality import assess


class Quality(unittest.TestCase):
    def record(self):
        return dict(result='COMPLETE', objects_absent=True,
                    receipt=dict(result='COMPLETE', reason='COMPLETE', stop_error=0,
                                 capture_error=0, errors=0, dropped=0, output_error=0,
                                 terminal=dict(valid=True, received=10, emitted=2,
                                               lost=0, rejected=0, owner_skipped=0)))

    def test_complete(self):
        self.assertEqual(assess(self.record())['status'], 'PASS')

    def test_bpf_program_misses_cannot_be_hidden_by_source_counter(self):
        r = self.record()
        r['receipt']['program_audit'] = dict(required=True, valid=True, programs=2, recursion_misses=0)
        self.assertEqual(assess(r)['status'], 'PASS')
        r['receipt']['program_audit']['recursion_misses'] = 1
        self.assertIn('program_audit.recursion_misses', assess(r)['defects'])
        r['receipt']['program_audit']['recursion_misses'] = None
        self.assertEqual(assess(r)['status'], 'BLOCKED')
        r['receipt']['program_audit'] = 'invalid'
        self.assertEqual(assess(r)['status'], 'BLOCKED')

    def test_historical_program_misses_explicitly_unmeasured(self):
        self.assertEqual(assess(self.record())['bpf_recursion_audit'], 'HISTORICAL_NOT_RECORDED')

    def test_last_unemitted_recursion_not_lost(self):
        r = self.record()
        r['collector'] = 'owner'
        self.assertEqual(assess(r)['status'], 'BLOCKED')
        r['receipt']['producer_recursion'] = dict(required=True, valid=True, skipped=0)
        self.assertEqual(assess(r)['status'], 'PASS')
        r['receipt']['producer_recursion']['skipped'] = 1
        self.assertIn('producer_recursion.skipped', assess(r)['defects'])

    def test_skipped_not_rescued_by_complete_label(self):
        r = self.record()
        r['receipt']['terminal']['owner_skipped'] = 25
        self.assertIn('terminal.owner_skipped', assess(r)['defects'])

    def test_old_receipt_not_upgraded(self):
        r = self.record()
        del r['receipt']['terminal']
        self.assertEqual(assess(r)['status'], 'BLOCKED')

    def test_budget_stop_is_safe_but_not_full_evidence(self):
        r = self.record()
        r['receipt'].update(result='PARTIAL', reason='ENTRY_RATE_LIMIT')
        value = assess(r)
        self.assertTrue(value['cleanup_verified'])
        self.assertTrue(value['budget_abort'])
        self.assertEqual(value['status'], 'FAIL')

    def test_missing_and_invalid_values_fail_closed(self):
        for value in (None, True, -1):
            r = self.record()
            r['receipt']['terminal']['received'] = value
            self.assertEqual(assess(r)['status'], 'BLOCKED')

    def test_combined_budget_is_not_ignored(self):
        r = self.record()
        r['process_cpu_budget'] = {'violation': 'COMBINED_PROCESS_CPU_TOTAL'}
        self.assertEqual(assess(r)['status'], 'FAIL')
