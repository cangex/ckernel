# SPDX-License-Identifier: GPL-2.0
import copy
import unittest
from maple_fixture_check import check_work


class MapleFixture(unittest.TestCase):
    def model(self):
        identities=[dict(id=i+1,generation=1) for i in range(2)]
        report={k:dict(status='PASS') for k in ('quality','scope_audit','maple','lifetimes')}
        report['calls']=[]; report['lifetimes']['release_entries']=[]
        logs=[]
        for i in range(2):
            log=['CIS_SESSION_CONTAINER host_pid=%d'%(101+i)]
            for cycle in range(2):
                for action in range(1,5):
                    begin=100+cycle*100+action*10
                    d=dict(cycle=cycle,action=action,begin_ns=begin,end_ns=begin+9,
                           tree0=1000+i*100,tree1=1001+i*100,generation=cycle+1,
                           cpu=i+(2 if action==3 else 0),verified=32*action if action<=2 else 0)
                    log.append('CIS_MAPLE_TRUTH '+' '.join('%s=%s'%p for p in d.items()))
                    if action<=2:
                        report['calls'].append(dict(actor=[i+1,1,101+i,1],call_ns=begin+2,
                            interval_ns=[begin+2,begin+5],sample_shift=0,object_samples=[],
                            maple_context=dict(tree_address=d['tree0' if action==1 else 'tree1'],
                                               allocation_bracket_ns=[begin+1,begin+6])))
            report['lifetimes']['release_entries'].append(dict(allocation_requester=[i+1,1,101+i,1],
                allocation_tree_context=dict(tree_address=1000+i*100),release_executor=dict(context='softirq')))
            logs.append('\n'.join(log))
        return dict(start_ns=1,end_ns=1000),logs,report,identities

    def test_private_copy_reuse_and_rcu_executor(self):
        args=self.model()
        self.assertEqual(check_work(*args)['status'],'PASS')
        self.assertEqual(check_work(*args[:2])['status'],'PASS')

    def test_source_tree_misattributed_as_copy_destination_rejected(self):
        args=list(self.model())
        args[2]['calls'][1]['maple_context']['tree_address']=1000
        self.assertIn('wrong_destination_0',check_work(*args)['errors'])

    def test_no_bridge_or_no_release_not_passed_by_hot_stack(self):
        for kind in ('missing','release','quality'):
            args=list(self.model())
            if kind=='missing': args[2]['calls'][0]['maple_context']=None
            elif kind=='release': args[2]['lifetimes']['release_entries']=[]
            else: args[2]['maple']['status']='FAIL'
            self.assertEqual(check_work(*args)['status'],'FAIL')

    def test_reuse_truth_generation_must_change(self):
        args=list(self.model())
        args[1][0]=args[1][0].replace('generation=2','generation=1')
        self.assertIn('truth_0',check_work(*args)['errors'])

    def test_private_trees_cannot_be_shared_or_time_nearest(self):
        args=list(self.model())
        args[1][1]=args[1][1].replace('tree0=1100','tree0=1000')
        self.assertIn('private_fixture_objects_shared',check_work(*args)['errors'])
        args=list(self.model())
        args[2]['calls'][0]['maple_context']['allocation_bracket_ns']=[1,900]
        self.assertIn('wrong_destination_0',check_work(*args)['errors'])
