# SPDX-License-Identifier: GPL-2.0
import copy
import unittest
from allocator_placement_check import check_case, nodes, case_order


class PlacementTruth(unittest.TestCase):
    ids=[dict(id=1,generation=1),dict(id=2,generation=1)]
    window=dict(start_ns=0,end_ns=1000)

    def example(self,case='split'):
        logs=[]; calls=[]; frees=[]
        for actor,node in enumerate(nodes(case)):
            text='CIS_SESSION_CONTAINER host_pid=%d\n'%(101+actor)
            for i in range(8):
                b=10+i*100; obj=1000+100*actor+i; who=[actor+1,1,101+actor,9]
                r=dict(index=i,requested_node=node,actual_node=node,allowed_node=node,cpu=actor,result=0,
                       object=obj,cache=99,begin_ns=b,allocated_ns=b+20,release_begin_ns=b+30,end_ns=b+40)
                text+='CIS_ALLOC_PLACEMENT '+' '.join('%s=%s'%x for x in r.items())+'\n'
                calls.append(dict(actor=who,call_ns=b+1,interval_ns=[b+1,b+19],cache_address=99,
                    object_address=obj,requested_node=node,observed_nodes=[node],sample_shift=0,
                    operation='single',requested=1,returned_count=1,rolled_back_count=0))
                frees.append(dict(allocation_requester=who,observation_key={'call_ns':b+1},object_address=obj,
                                  release_cpu=actor,release_entry_ns=b+31))
            logs.append(text)
        return logs,dict(quality={'status':'PASS'},scope_audit={'status':'PASS'},excluded={},calls=calls,
                         lifetimes=dict(status='PASS',release_entries=frees))

    def test_fixed_cases_and_no_observer_truth(self):
        self.assertEqual(len(case_order()),18)
        for c in ('local','remote','split'):
            logs,r=self.example(c)
            self.assertEqual(check_case(c,self.window,logs,r,self.ids)['captured'],16)
            self.assertEqual(check_case(c,self.window,logs,r,self.ids)['status'],'PASS')
            self.assertIsNone(check_case(c,self.window,logs)['selected_call_recall'])

    def test_wrong_node_actor_sample_and_release_rejected(self):
        for field,value in [('requested_node',1),('observed_nodes',[1]),('sample_shift',6),('object_address',2),('holder',[2,1])]:
            logs,r=self.example(); r['calls'][0][field]=value
            self.assertEqual(check_case('split',self.window,logs,r,self.ids)['status'],'FAIL')
        logs,r=self.example(); r['lifetimes']['release_entries'][0]['allocation_requester']=[2,1,102,9]
        self.assertEqual(check_case('split',self.window,logs,r,self.ids)['status'],'FAIL')

    def test_missing_duplicate_and_bad_policy_truth_rejected(self):
        logs,r=self.example(); r['calls'].pop()
        self.assertEqual(check_case('split',self.window,logs,r,self.ids)['status'],'FAIL')
        logs,r=self.example(); r['lifetimes']['release_entries'].append(copy.deepcopy(r['lifetimes']['release_entries'][0]))
        self.assertEqual(check_case('split',self.window,logs,r,self.ids)['status'],'FAIL')
        logs,r=self.example(); logs[0]=logs[0].replace('allowed_node=0','allowed_node=1')
        self.assertEqual(check_case('split',self.window,logs,r,self.ids)['status'],'FAIL')
