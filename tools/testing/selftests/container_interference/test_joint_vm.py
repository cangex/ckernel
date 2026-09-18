# SPDX-License-Identifier: GPL-2.0
import unittest
from joint_vm_check import workload,cpu_snapshot


class JointValidation(unittest.TestCase):
    def log(self):
        values=list(range(1,1501))
        return ('CIS_JOINT_WORK mode=file due_start_ns=100 begin_ns=110 end_ns=3000000100 offered=1500 completed=1500 errors=0 timeouts=0 period_ns=2000000 timeout_ns=100000000 p99_ns=1485 max_ns=1500 latency_sum_ns=1125750\n'
                +'CIS_JOINT_LATENCIES '+','.join(str(v) for v in values)+'\n')
    def test_p99_is_arrival_relative_and_verified_from_all_samples(self):
        row=workload(self.log()); self.assertEqual(row['p99_ns'],1485)
        self.assertEqual(row['throughput_per_second'],500)
        for old,new in [('p99_ns=1485','p99_ns=1'),('errors=0','errors=1'),('timeouts=0','timeouts=1')]:
            with self.assertRaises(ValueError): workload(self.log().replace(old,new))
    def test_cpu_categories_not_added_to_observer_claim(self):
        self.assertEqual(cpu_snapshot('cpu 1 2 3 4 5 6 7 8\ncpu0 1 2 3 4 5 6 7 8\nctxt 99\n')['cpu0'][6],7)
        with self.assertRaises(ValueError): cpu_snapshot('cpu 1 2\n')
