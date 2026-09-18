# SPDX-License-Identifier: GPL-2.0
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'container_interference'))
from counter_check import check


class CounterTruth(unittest.TestCase):
    def sample(self):
        report=dict(quality=dict(status='PASS'), calls=[],
                    address_candidates=[dict(address=200,field='usage')])
        logs=[]
        for pid,ident in ((10,1),(20,2)):
            for op,start in (('charge',12),('uncharge',16)):
                report['calls'].append(dict(leaf_address=100,operation=op,interval_ns=[start,start+2],
                    actor=[ident,1,pid|(pid<<32),1],steps=[dict(address=a,stage='usage_add' if op=='charge' else 'usage_sub') for a in (100,200)]))
            logs.append('CIS_SESSION_CONTAINER host_pid=%d\n'%pid+
                'CIS_COUNTER_TRUTH begin_ns=10 end_ns=20 leaf=100 parent=200 failed=0 success=1 final_leaf=0 final_parent=0 operation=0 pages=1 cpu=0\n')
        return report,logs

    def test_overlapping_same_object_calls_use_actor_identity(self):
        report,logs=self.sample(); result=check(report,logs)
        self.assertEqual(result['status'],'PASS')
        self.assertEqual(result['matched_calls'],4)

    def test_wrong_task_or_container_cannot_be_joined(self):
        report,logs=self.sample(); report['calls'][0]['actor'][2]=30|(30<<32)
        self.assertEqual(check(report,logs)['status'],'FAIL')
        report,logs=self.sample(); report['calls'][0]['actor'][0]=2
        self.assertEqual(check(report,logs,identities=[dict(id=1,generation=1),dict(id=2,generation=1)])['status'],'FAIL')

    def test_duplicate_and_missing_steps_fail(self):
        report,logs=self.sample(); report['calls'].append(copy.deepcopy(report['calls'][0]))
        self.assertEqual(check(report,logs)['status'],'FAIL')
        report,logs=self.sample(); report['calls'][0]['steps'].pop()
        self.assertEqual(check(report,logs)['status'],'FAIL')


if __name__=='__main__': unittest.main()
