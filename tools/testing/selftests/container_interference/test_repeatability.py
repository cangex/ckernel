# SPDX-License-Identifier: GPL-2.0
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]/'container_interference'))
from repeatability_report import PROTOCOL, analyze


def fixture(boot, bias=0):
    source = {k: 'a'*64 for k in ('workload_sha256','launcher_sha256','kernel_notes_sha256','cmdline_sha256','runner_sha256')}
    plan = dict(protocol=PROTOCOL, boot_index=boot, boot_id='%08d-0000-0000-0000-000000000000' % boot, source=source)
    lines = ['CIS_REPEATABILITY_PLAN '+json.dumps(plan)]; files = []
    for w in ('throughput', 'latency'):
        for p in range(5):
            for label in (('A','B') if (boot*5+p)%2==0 else ('B','A')):
                for role in range(2):
                    path = '/tmp/repeatability/%s-%d-%s-%d.log' % (w,p,label,role)
                    case = dict(workload=w,pair=p,label=label,role=role,cpu=(role^((boot*5+p)%2))*2,path=path,start_ns=1_000_000_000,exit_code=0)
                    lines.append('CIS_REPEATABILITY_CASE '+json.dumps(case))
                    value = 60000+ (bias if label=='B' else 0)
                    body = 'CIS_WARMUP operations=4096 end_ns=999999999 before_start=1\n'
                    if w=='throughput':
                        body += 'CIS_RESULT operations=10000 start_ns=1000000000 end_ns=3000000000 scheduled_end_ns=3000000000 errors=0\n'
                    else:
                        body += 'CIS_LATENCY count=4000 rate=2000 start_ns=1000000000 end_ns=3000000000 p99_ns=%d max_ns=1000000 timeouts=0\n' % value
                        body += 'CIS_LATENCY_PARTS tail_count=40 timerslack_ns=50000\n'
                    files.append('CIS_FILE '+path+'\n'+body)
    return ('\n'.join(lines+['CIS_REPEATABILITY_DONE=0','CIS_PROFILE_VM_EXIT=0']+files)+'\n').encode()


class Repeatability(unittest.TestCase):
    def test_identical_not_observer_admission(self):
        result = analyze([('boot0',fixture(0)),('boot1',fixture(1))])
        self.assertEqual(result['calibration_status'],'PASS')
        self.assertFalse(result['observer_admission'])
        self.assertEqual(len(result['rows']),4)
        self.assertEqual(result['rows'][0]['pooled']['n'],10)

    def test_difference_is_not_measurement_pass(self):
        result=analyze([('a',fixture(0,3000)),('b',fixture(1,3000))])
        self.assertEqual(result['calibration_status'],'BLOCKED')

    def test_boot_blocks_not_hidden_by_pooling(self):
        result=analyze([('a',fixture(0,3000)),('b',fixture(1,-3000))])
        self.assertEqual(result['calibration_status'],'BLOCKED')
        self.assertEqual(result['rows'][2]['pooled']['mean_pct'],0)

    def test_failed_boot_missing_duplicate_mixed_source(self):
        for a,b in [(fixture(0),fixture(0)),(fixture(0),fixture(1).replace(b'VM_EXIT=0',b'VM_EXIT=1')),
                    (fixture(0),fixture(1).replace(b'"runner_sha256": "'+b'a'*64,b'"runner_sha256": "'+b'b'*64)),
                    (fixture(0),fixture(1).replace(b'"exit_code": 0',b'"exit_code": 1',1))]:
            with self.assertRaises(ValueError):analyze([('a',a),('b',b)])

    def test_no_partial_selection_or_late_warmup(self):
        for old,new in [(b'end_ns=999999999',b'end_ns=1000000001'),
                        (b'count=4000',b'count=3999'),(b'"cpu": 0',b'"cpu": 7'),
                        (b'timerslack_ns=50000',b'timerslack_ns=1')]:
            with self.assertRaises(ValueError):
                analyze([('a',fixture(0)),('b',fixture(1).replace(old,new,1))])

    def test_missing_plan_marker_or_raw(self):
        for marker in (b'CIS_REPEATABILITY_DONE=0',b'CIS_REPEATABILITY_PLAN ',b'CIS_FILE '):
            with self.assertRaises(ValueError):
                analyze([('a',fixture(0)),('b',fixture(1).replace(marker,b'REMOVED ',1))])


if __name__=='__main__':unittest.main()
