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
                 episode_interval_ns=[30,39],completions=[dict(bytes=262144 if shared else 131072,status=0)],
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

    def test_cannot_satisfy_coverage_with_old_wrong_or_partial_io(self):
        for field,value in (('episode_interval_ns',[1,9]),('episode_interval_ns',[30,50]),
                            ('completions',[dict(bytes=4096,status=0)]),('completions',[dict(bytes=131072,status=1)])):
            args=self.inputs(); args[5]['requests'][0][field]=value
            self.assertEqual(check_case(*args)['status'],'FAIL')

    def test_truth_window_sharedness_and_durable_content(self):
        for index,value in ((0,'shared'),(3,[15,40]),(3,[30,101]),(4,[True,False])):
            args=self.inputs(); args[index]=value
            self.assertEqual(check_case(*args)['status'],'FAIL')
        args=self.inputs(); args[2][0]=args[2][0].replace('buffered=1','buffered=0')
        self.assertEqual(check_case(*args)['status'],'FAIL')

    def bridge_inputs(self,shared=False):
        args=self.inputs(shared); report=args[5]
        contexts=[dict(request=[300+i,30],context=dict(exclusive_dirtier=None,blocking_container=None,
            device=[8,0 if shared else i],ino=10 if shared else 10+i,executor=[0,0,100,1]))
            for i in range(1 if shared else 2)]
        for i,r in enumerate(report['requests']): r.update(request=300+i,episode_ns=30)
        report['writeback']=dict(coverage='AVAILABLE',request_links=contexts,dirty_observations=[
            dict(actor=[i+1,1,200+i,1],device=[8,0 if shared else i],ino=10 if shared else 10+i,time_ns=15)
            for i in range(2)])
        return args

    def test_bridge_checks_independent_inode_and_both_dirtying_containers(self):
        for shared in (False,True):
            args=self.bridge_inputs(shared); r=check_case(*args)
            self.assertEqual(r['status'],'PASS',r)
            self.assertEqual(r['inode_request_link'],'CLOSED_NATIVE_CONTEXT')
            self.assertEqual(len(r['dirty_transition_actors']),2)
        for field,value in (('ino',999),('device',[8,99]),('executor',[1,1,100,1]),('exclusive_dirtier',[1,1])):
            args=self.bridge_inputs(); args[5]['writeback']['request_links'][0]['context'][field]=value
            self.assertEqual(check_case(*args)['status'],'FAIL')
        args=self.bridge_inputs(True); args[5]['writeback']['dirty_observations'].pop()
        self.assertEqual(check_case(*args)['status'],'FAIL')
