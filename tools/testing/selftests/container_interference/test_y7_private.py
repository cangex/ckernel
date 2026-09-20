# SPDX-License-Identifier: GPL-2.0
import unittest
from y7_private_check import workload,order,captures,ROLES

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
