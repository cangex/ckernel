# SPDX-License-Identifier: GPL-2.0
import unittest
from y7_private_check import workload,order,captures,validate_plan,ROLES

class PrivateJoint(unittest.TestCase):
    def log(self):
        values=list(range(1,6001))
        return ('Y7_PRIVATE actor=0 dev=10 inode=20 due=100 begin=110 end=18000000100 offered=6000 completed=6000 errors=0 timeouts=0 period=3000000 timeout=100000000 p99=5940 max=6000 sum=18003000\n'
                +'Y7_LATENCIES '+','.join(str(v) for v in values)+'\n')
    def test_complete_arrival_samples(self):
        self.assertEqual(workload(self.log())['p99'],5940)
        for old,new in [('p99=5940','p99=1'),('errors=0','errors=1'),('actor=0','actor=4'),('completed=6000','completed=5999')]:
            with self.assertRaises(ValueError):workload(self.log().replace(old,new))
    def test_frozen_roles_and_session_capacity(self):
        self.assertEqual(len(order()),9)
        self.assertEqual(sum(len(captures(v['mode'])) for v in order()),21)
        self.assertEqual(order()[3]['mode'],'profile')
        self.assertEqual(set(i for r in ROLES for i in r),{0,1,2,3})
        self.assertFalse(set(('fd','owner','net','allocator','sync','rwsem'))&set(captures('profile')))
        with self.assertRaises(ValueError): captures('unknown')

    def test_separate_devices_and_private_directories_are_not_asserted_by_name(self):
        p=dict(schema='cis-y7-private-plan-v1',order=order(),arrangement='separate',rounds=3,
            offered=6000,period_ns=3_000_000,timeout_ns=100_000_000,window_ms=2000,
            management_cpu=7,cpus=[0,1,2,3],directories=[dict(path='/fs%d/private%d'%(i%2,i),
                disk=i%2,dev=10+i%2,inode=20+i) for i in range(4)])
        validate_plan(p)
        p['directories'][1]['dev']=10
        with self.assertRaises(ValueError):validate_plan(p)
