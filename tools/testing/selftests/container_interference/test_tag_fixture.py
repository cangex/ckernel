# SPDX-License-Identifier: GPL-2.0
import copy
import unittest
from tag_fixture_check import check, order


class TagFixtureTests(unittest.TestCase):
    def example(self,case):
        truth=[dict(actor=0,op=0,result=0,depth=4,before_ns=10,after_ns=20,queue=999) for _ in range(3 if case=='available' else 4)]
        truth.append(dict(actor=1,op=0,result=-11 if case=='nowait' else 0,depth=4,
            before_ns=30,after_ns=100_000_000,disk=int(case=='private'),nowait=int(case=='nowait'),
            tid=100,task_start=1,queue=998 if case=='private' else 999))
        if case=='exhausted': truth.append(dict(actor=0,op=1,result=0,depth=4,before_ns=70_000_000,after_ns=80_000_000))
        return dict(case=case,truth=truth,held_before=[3 if case=='available' else 4,0],
                    window=dict(start_ns=1,end_ns=200_000_000))

    def test_frozen_order_is_three_alternating_pairs(self):
        self.assertEqual(len(order()),24)
        for i in range(0,24,6):
            self.assertIn('-off-0',order()[i]); self.assertIn('-block-1',order()[i+2])

    def test_truth_off_controls(self):
        for case in ('exhausted','private','available','nowait'):
            self.assertEqual(check(self.example(case))['status'],'PASS')

    def test_negative_requires_zero_tag_episodes(self):
        for case in ('private','available'):
            report=dict(quality=dict(status='PASS'),scope_audit=dict(status='PASS'),requests=[],tag_waits=[])
            self.assertEqual(check(self.example(case),report,[])['status'],'PASS')
            report['quality']['status']='FAIL'
            self.assertEqual(check(self.example(case),report,[])['status'],'FAIL')

    def test_exact_call_join_and_actual_sleep(self):
        report=dict(quality=dict(status='PASS'),scope_audit=dict(status='PASS'),requests=[],tag_waits=[
            dict(tid=(100<<32)|100,task_start=1,queue=999,container=[2,1],identity_changes=[],blocking_container=None,
                 request_allocation_success='NOT_ESTABLISHED',interval_ns=[40,90_000_000],outcome='TAG_FOUND',
                 sleep_intervals=[dict(interval_ns=[50,85_000_000])])])
        identities=[dict(id=1,generation=1),dict(id=2,generation=1)]
        self.assertEqual(check(self.example('exhausted'),report,identities)['status'],'PASS')
        for field,value in (('queue',998),('blocking_container',1),('sleep_intervals',[]),('container',[1,1])):
            bad=copy.deepcopy(report); bad['tag_waits'][0][field]=value
            self.assertEqual(check(self.example('exhausted'),bad,identities)['status'],'FAIL')
