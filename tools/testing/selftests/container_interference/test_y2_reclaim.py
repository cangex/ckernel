# SPDX-License-Identifier: GPL-2.0
import copy
import unittest
from y2_reclaim_check import pressure


class ReclaimPressure(unittest.TestCase):
    def groups(self):
        return [dict(path='/sys/fs/cgroup/test/'+str(i),cgroup_id=10+i,
                     **{'memory.high':'max','memory.events.local':'high 0\nmax 0\noom 0\n'}) for i in range(6)]

    def test_counts_do_not_name_blocker_or_native_target(self):
        before=self.groups(); after=copy.deepcopy(before)
        after[0]['memory.events.local']='high 3\nmax 0\noom 0\n'
        report=pressure(before,after)
        self.assertEqual(report[0]['local_events']['high'],3)
        self.assertTrue(all(r['blocking_container'] is None and r['reclaim_target']=='UNKNOWN' for r in report))

    def test_reuse_reconfiguration_reset_and_capacity(self):
        for key,value in [('cgroup_id',90),('memory.high','1'),('path','/other'),('memory.events.local','high -1\nmax 0\noom 0\n')]:
            before=self.groups(); after=copy.deepcopy(before); after[0][key]=value
            with self.assertRaises(ValueError): pressure(before,after)
        with self.assertRaises(ValueError): pressure([],[])
