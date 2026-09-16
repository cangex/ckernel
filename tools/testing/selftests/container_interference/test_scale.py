# SPDX-License-Identifier: GPL-2.0
import pathlib
import json
import sys
import unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3] / 'container_interference'))
from scale_run import generate
from scale_report import analyze
from overhead import interval
from window_check import check
from scale_plan import matrix


class Scale(unittest.TestCase):
    def test_empty_cannot_pass_scale(self):
        result = analyze('')
        self.assertFalse(result['pass'])
        self.assertFalse(result['coverage_valid'])

    def test_missing_window_is_not_ready(self):
        self.assertFalse(check('')['pass'])

    def test_no_bypass_of_s2(self):
        with self.assertRaises(ValueError):
            generate({'status': 'READY_FOR_WINDOW_VALIDATION'}, {'pass': True}, b'{}')

    def test_interval_requires_predeclared_size(self):
        self.assertEqual(interval([0]*6), [None, None])
        self.assertEqual(interval([0]*20), [0, 0])

    def test_complete_synthetic_matrix_exercises_parser_not_performance(self):
        lines, observers = [], []
        for pid, case in enumerate(matrix(), 100):
            stem = 'scale-{family}-{count}-{round}-{workload}-{mode}'.format(**case)
            start=pid*100000000000
            lines += [f'CIS_FILE /tmp/{stem}.log',
                      f'CIS_FLEET_BEGIN observer_pid={pid} start_ns={start} duration={case["seconds"]}']
            for slot in range(case['count']):
                if case['workload']=='bench':
                    lines.append(f'CIS_RESULT cgroup=0::/cis-fleet-{slot} operations=100000 last_batch_ops=256 errors=0')
                else:
                    lines.append(f'CIS_LATENCY cgroup=0::/cis-fleet-{slot} p99_ns=1000 timeouts=0')
            if case['mode']=='off':
                continue
            observers.append(f'CIS_FILE /tmp/observer-{pid}.jsonl')
            for slot in range(case['count']):
                observers += [json.dumps({'kind':'register','id':slot+1,'name':f'container-{slot}'}),
                              json.dumps({'kind':'IP','id':slot+1,'detail':f'sample_time_ns={start+1}'})]
            if case['mode']=='diag':
                observers.append(json.dumps({'kind':'diagnostic_start','detail':f'start_ns={start} deadline_ns={start+2000000000} ready_ns={start-1}'}))
        result=analyze('\n'.join(lines+observers))
        self.assertTrue(result['pass'])
        self.assertEqual(result['case_count'],200)
        self.assertFalse(analyze('\n'.join(lines+lines+observers))['pass'])


if __name__ == '__main__':
    unittest.main()
