# SPDX-License-Identifier: GPL-2.0
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'container_interference'))
from slub_fixture_check import check
from test_slub_report import row


class SlubFixture(unittest.TestCase):
    def data(self):
        jobs=[]; logs={}
        for i, actor in enumerate((0,1)):
            args=dict(command='operate',node=0,hold=5000 if i==0 else 0,wait_node=0,wait_holders=i,mode=0)
            name=str(i); jobs.append(dict(log=name,actor_index=actor,token=1,arguments=args))
            r=dict(command=2,hold_us=args['hold'],wait_node=0,wait_holders=i,mode=0,token=1,node=0,
                task=101+i,cache=0xffff123400001000,object=100,outcome=1,
                begin_ns=50000 if i==0 else 200000,acquired_ns=100000 if i==0 else 600000,
                release_ns=500000 if i==0 else 700000,end_ns=550000 if i==0 else 750000)
            logs[name]='CIS_SLUB_TRUTH '+' '.join('%s=%s'%v for v in r.items())
        events=[row(110000,3,1),row(210000,2,2),row(490000,4,1),row(610000,3,2),row(690000,4,2)]
        return events,jobs,logs,[dict(id=1,generation=1),dict(id=2,generation=1)],'shared',dict(start_ns=1,end_ns=900000)

    def test_positive_with_64bit_cache(self):
        out=check(*self.data())
        self.assertEqual(out['status'],'PASS',out)
        self.assertEqual((out['eligible'],out['captured_eligible']),(1,1))

    def test_wrong_native_task_not_accepted(self):
        a=list(self.data()); a[2]=copy.deepcopy(a[2]); a[2]['0']=a[2]['0'].replace('task=101','task=999')
        out=check(*a)
        self.assertIn('wrong_holder_object_or_lifetime',out['errors'])

    def test_no_events_not_unknown_success(self):
        a=list(self.data()); a[0]=[]
        self.assertEqual(check(*a)['status'],'FAIL')

    def test_window_misalignment_fails(self):
        a=list(self.data()); a[5]['end_ns']=600000
        self.assertIn('truth_outside_window',check(*a)['errors'])

    def test_private_node_addresses_remain_distinct(self):
        a=list(self.data()); a[4]='private'
        a[2]['1']=a[2]['1'].replace('object=100','object=200')
        for i in (1,3,4): a[0][i]['detail']=a[0][i]['detail'].replace('object=100','object=200')
        self.assertEqual(check(*a)['status'],'PASS')

    def test_missing_acquire_not_converted_to_holder_from_release(self):
        a=list(self.data()); a[4]='unseenHolder'; a[0]=a[0][1:]
        out=check(*a)
        self.assertEqual(out['status'],'PASS',out)
        self.assertEqual(out['edges'],0)
        self.assertTrue(out['unobserved_acquire_negative'])

    def test_actual_unseen_holder_must_exist_for_negative_credit(self):
        a=list(self.data()); a[4]='unseenHolder'; a[0]=a[0][1:]
        a[2]['0']=a[2]['0'].replace('release_ns=500000','release_ns=150000')
        self.assertIn('unobserved_acquire_not_exercised',check(*a)['errors'])

    def test_unselected_cache_is_not_a_zero_event_success_without_truth(self):
        a=list(self.data()); a[4]='outsideCache'; a[0]=[]
        self.assertEqual(check(*a)['status'],'PASS')
        a[2]['0']=a[2]['0'].replace('release_ns=500000','release_ns=150000')
        self.assertIn('unselected_contended_operation_not_exercised',check(*a)['errors'])

    def test_unselected_node_must_not_emit_holders(self):
        a=list(self.data()); a[4]='outsideNode'
        for j in a[1]: j['arguments']['node']=1; j['arguments']['wait_node']=1
        a[2]={k:v.replace('node=0','node=1') for k,v in a[2].items()}
        self.assertIn('unselected_operations_emitted',check(*a)['errors'])
        a[0]=[]
        self.assertEqual(check(*a)['status'],'PASS')


if __name__=='__main__': unittest.main()
