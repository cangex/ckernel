# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import json
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[3]/'container_interference'))
from idle_cost_report import analyze, paired


class IdleCostTests(unittest.TestCase):
    def test_fixed_count(self):
        self.assertEqual(paired([0]*9, 1)['status'], 'BLOCKED')
        self.assertEqual(paired([0]*11, 1)['status'], 'BLOCKED')

    def test_status_uses_interval(self):
        self.assertEqual(paired([.2]*10, 1)['status'], 'PASS')
        self.assertEqual(paired([3]*10, 2)['status'], 'FAIL')
        self.assertEqual(paired([-10, 10]*5, 2)['status'], 'UNDETERMINED')

    def test_log_marker_does_not_satisfy_missing_evidence(self):
        with self.assertRaises(KeyError): analyze('CIS_IDLE_COST_COMPLETE=1\nCIS_PROFILE_VM_EXIT=0')

    def test_complete_multiline_plan_and_all_pairs(self):
        lines = ['CIS_IDLE_COST_COMPLETE=1', 'CIS_PROFILE_VM_EXIT=0']
        def artifact(name, data):
            lines.extend(['CIS_FILE /tmp/'+name, data])
        artifact('plan.json', json.dumps(dict(pairs=10, seconds=10, arrival_rate=2000), indent=2))
        s = dict(busy_ticks=100, hz=100, cgroup_usage_us=[100, 100], begin_ns=1,
                 end_ns=20, used_vm_bytes=1000)
        for workload in ('throughput', 'latency'):
            for n in range(10):
                for mode in ('off', 'idle'):
                    name = '%s-%02d-%s' % (workload, n, mode)
                    artifact(name+'.json', json.dumps(dict(all_children_exit_zero=True,
                        samples=[s], before_controller=s, after_stop=s), indent=2))
                    for role in range(2):
                        result = ('CIS_RESULT operations=100 errors=0 start_ns=1 end_ns=10000000001' if workload == 'throughput' else
                                  'CIS_LATENCY count=20000 p99_ns=50000 start_ns=1 end_ns=10000000001\nCIS_LATENCY_PARTS tail_count=200 timerslack_ns=50000')
                        artifact('%s-%d.log' % (name, role), result)
        result = analyze('\n'.join(lines))
        self.assertTrue(result['complete'])
        self.assertFalse(result['phase_complete'])
        self.assertFalse(result['resource_budget_pass'])
        self.assertEqual(len(result['resources']), 40)
        self.assertTrue(all(row['status'] == 'PASS' for row in result['comparisons'].values()))


if __name__ == '__main__': unittest.main()
