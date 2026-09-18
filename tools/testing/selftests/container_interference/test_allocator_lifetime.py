# SPDX-License-Identifier: GPL-2.0
import json
import unittest
import test_allocator_report
from allocator_lifetime import correlate


class AllocationLifetime(unittest.TestCase):
    def sample(self,context=0,free_time=50,object_address=500,ordinal=6,call_ns=10):
        d=dict(protocol=1,sample_time_ns=free_time,call_ns=call_ns,allocation_time_ns=17,
            allocation_ordinal=ordinal,tid=102,task_start=1,cpu=3,cache=100,object=object_address,
            context=context,caller=600,stack_id=-1,executor_tid=202 if not context else 0,
            executor_start=2 if not context else 0,executor_id=0,executor_generation=0)
        return dict(session_id='7',kind='ALLOC_RELEASE',id=1,generation=1,
                    detail=' '.join('%s=%s'%p for p in d.items()))

    def run_rows(self,extra):
        helper=test_allocator_report.AllocatorReport()
        rows=helper.rows([1,2,3,6,15,16,20])+extra
        # Unit model of an accepted capture; runtime audit is checked separately.
        report=helper.run_rows(rows)
        report['scope_audit']={'status':'PASS'}
        return correlate(helper.record(),'\n'.join(json.dumps(r) for r in rows).encode(),report,{})

    def test_cross_cpu_and_host_executor_preserve_requester(self):
        result=self.run_rows([self.sample()])
        self.assertEqual(result['status'],'PASS',result)
        item=result['release_entries'][0]
        self.assertEqual(item['allocation_requester'],[1,1,102,1])
        self.assertEqual(item['allocation_cpu'],0); self.assertEqual(item['release_cpu'],3)
        self.assertIsNone(item['release_executor']['container'])
        self.assertEqual(item['release_executor']['tid'],202)
        self.assertEqual(item['release_completed'],'UNOBSERVED')
        self.assertIsNone(item['blocking_container'])

    def test_softirq_is_not_interrupted_task_owner(self):
        result=self.run_rows([self.sample(context=1)])
        self.assertEqual(result['status'],'PASS')
        item=result['release_entries'][0]
        self.assertIsNone(item['release_executor']['tid'])
        self.assertEqual(item['release_executor']['context'],'softirq')

    def test_old_generation_wrong_object_and_double_free_rejected(self):
        for row in (self.sample(call_ns=9),self.sample(object_address=501),self.sample(ordinal=2),self.sample(free_time=15)):
            self.assertEqual(self.run_rows([row])['status'],'FAIL')
        self.assertEqual(self.run_rows([self.sample(),self.sample()])['status'],'FAIL')

    def test_window_start_no_allocation_not_guessed(self):
        helper=test_allocator_report.AllocatorReport()
        result=helper.run_rows([self.sample()])['lifetimes']
        self.assertEqual(result['status'],'FAIL')
        self.assertFalse(result['release_entries'])

    def test_missing_release_is_open_lifetime_not_zero_age(self):
        result=self.run_rows([])
        self.assertEqual(result['allocations_without_release'],1)
        self.assertFalse(result['release_entries'])
