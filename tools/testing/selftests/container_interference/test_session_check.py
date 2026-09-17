# SPDX-License-Identifier: GPL-2.0
import importlib.util
import json
from pathlib import Path
import sys
import unittest
directory=Path(__file__).resolve().parents[3]/'container_interference'
sys.path.insert(0,str(directory))
import session_check

class EvidenceChecks(unittest.TestCase):
    def test_missing_evidence_is_not_pass(self):
        result=session_check.analyze('CIS_PROFILE_VM_FUNCTIONAL_PASS=1\nCIS_PROFILE_VM_EXIT=0')
        self.assertFalse(result['phase_complete'])
        self.assertEqual(result['repeat']['ip']['status'],'BLOCKED')
        self.assertTrue(all(row['status']=='BLOCKED' for row in result['cost']))

    def test_small_n_has_no_fabricated_ci(self):
        self.assertEqual(session_check.interval([0,0,0])['status'],'BLOCKED')

    def test_pair_interval(self):
        result=session_check.interval([0,1,2,3,4])
        self.assertEqual(result['mean_pct'],2)
        self.assertGreater(result['upper95_pct'],2)

    def test_file_boundaries(self):
        result=session_check.extract('CIS_FILE /a\nx\nCIS_FILE /b\ny\n')
        self.assertEqual(result,{'/a':'x','/b':'y'})

    def test_partial_repeats_cannot_pass_cleanup_as_capture(self):
        text = '\n'.join('CIS_FILE /records/%d.json\n%s' % (i, json.dumps(dict(
            session_id=str(i), nonce='repeatip%d'%i, state='IDLE', result='PARTIAL',
            objects_absent=True, inventory=dict(ip_perf_cpus=8), receipt=dict(stop_error=0)))) for i in range(100))
        result = session_check.analyze(text)
        self.assertNotEqual(result['repeat']['ip']['status'], 'PASS')

    def test_incomplete_cost_windows_do_not_receive_performance_pass(self):
        records = {str(i):dict(nonce='costthroughput%downer'%i, result='COMPLETE', objects_absent=True,
                       receipt=dict(result='COMPLETE', stop_error=0, dropped=0, errors=0, output_error=0)) for i in range(5)}
        self.assertEqual(session_check.capture_quality(records, 'throughput', 'owner')['status'], 'PASS')
        records['2']['result'] = 'PARTIAL'
        records['2']['receipt']['reason'] = 'ENTRY_RATE_LIMIT'
        self.assertEqual(session_check.capture_quality(records, 'throughput', 'owner')['status'], 'FAIL')
        del records['2']
        self.assertEqual(session_check.capture_quality(records, 'throughput', 'owner')['status'], 'BLOCKED')

if __name__=='__main__':unittest.main()
