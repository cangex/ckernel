# SPDX-License-Identifier: GPL-2.0
from copy import deepcopy
import unittest
from writeback_check import case_order,check_case


class WritebackTruth(unittest.TestCase):
    def inputs(self, shared=False):
        window=dict(start_ns=1,end_ns=100)
        logs=[f'CIS_WRITEBACK_WRITE role={i} begin_ns=10 end_ns=20 inode={10 if shared else 10+i} major=8 minor={0 if shared else i} offset={i*131072} bytes=131072 pattern={0x35+i} buffered=1\nCIS_WRITEBACK_DONE errors=0'
              for i in range(2)]
        report=dict(quality=dict(status='PASS'),scope_audit=dict(status='PASS'),requests=[
            dict(initial_dirtier=None,inode_owner=None,blocking_container=None,admission='bio_billing_root',
                 selected_container=[i+1,1],submitter=[0,0,100,1],submitter_kernel_thread=True,
                 operation=1,devices=[[8,0 if shared else i]],terminal='data_completion',start_stack_leaf_to_root=['wb_workfn'])
            for i in range(1 if shared else 2)])
        return [ 'shared' if shared else 'private',window,logs,[30,40],[True,True],report,[dict(id=i+1,generation=1) for i in range(2)]]

    def test_alternation_and_shared_inode_billing_not_dirtier(self):
        self.assertEqual(len(case_order()),12)
        self.assertEqual(case_order()[4:6],['private-block-r2','private-off-r2'])
        for shared in (False,True):
            r=check_case(*self.inputs(shared)); self.assertEqual(r['status'],'PASS',r)
            self.assertEqual(r['dirtying_actor_link'],'UNOBSERVED')

    def test_empty_or_wrong_executor_not_positive_coverage(self):
        args=self.inputs(); args[5]['requests']=[]
        self.assertIn('no_real_background_writeback',check_case(*args)['errors'])
        for key,val in (('submitter',[1,1,100,1]),('initial_dirtier',[1,1]),('inode_owner',9),
                        ('blocking_container',[2,1]),('submitter_kernel_thread',False),('start_stack_leaf_to_root',[])):
            args=self.inputs(); args[5]['requests'][0][key]=val
            self.assertEqual(check_case(*args)['status'],'FAIL')

    def test_truth_window_sharedness_and_durable_content(self):
        for index,value in ((0,'shared'),(3,[15,40]),(3,[30,101]),(4,[True,False])):
            args=self.inputs(); args[index]=value
            self.assertEqual(check_case(*args)['status'],'FAIL')
        args=self.inputs(); args[2][0]=args[2][0].replace('buffered=1','buffered=0')
        self.assertEqual(check_case(*args)['status'],'FAIL')
