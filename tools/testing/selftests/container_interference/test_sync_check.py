# SPDX-License-Identifier: GPL-2.0
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'container_interference'))
from sync_check import check


class SyncTruth(unittest.TestCase):
    def setUp(self):
        self.event=dict(address='0x100',task_id=(71<<32)|73,container_id=42,
                        interval_ns=[10,20],access_class='spin',holder=None,other_container_identified=False)
        self.report=dict(candidates=[self.event],quality=dict(status='PASS'))
        self.row=dict(object=256,generation=1,tid=73,cgroup_id=42,operation=0,result=0,begin_ns=9,acquired_ns=21)

    def logs(self,*rows): return ['CIS_SYNC_TRUTH '+json.dumps(row) for row in rows]

    def test_exact_object_actor_and_interval(self):
        result=check(self.report,self.logs(self.row),True)
        self.assertEqual(result['status'],'PASS')
        self.assertEqual(result['matched_intervals'],1)
        self.assertIsNone(result['eligible_recall'])

    def test_other_container_wrong_tid_wrong_time_rejected(self):
        for key,value in [('cgroup_id',43),('tid',74),('acquired_ns',19),('begin_ns',11),('result',-16)]:
            row=dict(self.row,**{key:value})
            self.assertEqual(check(self.report,self.logs(row),True)['status'],'FAIL')

    def test_reused_address_requires_unique_matching_operation(self):
        later=dict(self.row,generation=2,begin_ns=30,acquired_ns=40)
        result=check(self.report,self.logs(self.row,later),True)
        self.assertEqual(result['status'],'PASS')
        self.assertEqual(result['matches'][0]['generation'],1)
        ambiguous=dict(self.row,generation=2)
        self.assertEqual(check(self.report,self.logs(self.row,ambiguous),True)['status'],'FAIL')

    def test_no_positive_or_fake_owner_does_not_pass(self):
        report=deepcopy(self.report);report['candidates']=[]
        self.assertEqual(check(report,self.logs(self.row),True)['status'],'FAIL')
        self.event['holder']=[43,1,99]
        self.assertEqual(check(self.report,self.logs(self.row),True)['status'],'FAIL')


if __name__=='__main__':unittest.main()
