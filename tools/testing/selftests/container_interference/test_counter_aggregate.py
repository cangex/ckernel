# SPDX-License-Identifier: GPL-2.0
import copy
import unittest
from counter_aggregate import aggregate
import test_counter_report


class CounterAggregate(unittest.TestCase):
    def report(self,fail=False):
        helper=test_counter_report.CounterReport()
        report=helper.run_rows(helper.version2(helper.call(fail=fail)+helper.call(actor=2,start=30,leaf=101,fail=fail)))
        report['object_scope']=dict(boot_id='12345678-1234-1234-1234-123456789abc',session_id='7')
        return report

    def selection(self):
        return dict(boot_id='12345678-1234-1234-1234-123456789abc',session_id='7',
            objects=[dict(address=200,generation=1200,field='usage')])

    def test_sampled_updates_and_failure_do_not_multiply_wall_time(self):
        out=aggregate(self.report(True),self.selection())
        item=out['objects'][0]
        self.assertEqual(item['relation'],'shared_counter_updates')
        self.assertEqual(item['actors'][0]['sampled_calls'],1)
        self.assertEqual(item['actors'][0]['failed_calls'],1)
        self.assertEqual(sum(item['actors'][0]['call_wall_ns_log2'].values()),1)
        self.assertEqual(item['actors'][0]['update_stages'],{'usage_add':1,'limit_reverse':1})
        self.assertIsNone(item['holder'])
        self.assertEqual(out['live_source_aggregation'],'NOT_IMPLEMENTED')

    def test_old_boot_generation_missing_or_excess_keys_rejected(self):
        for field,value in (('boot_id','00000000-0000-0000-0000-000000000000'),('session_id','8')):
            s=self.selection(); s[field]=value
            with self.assertRaises(ValueError): aggregate(self.report(),s)
        s=self.selection(); s['objects'][0]['generation']=0
        with self.assertRaises(ValueError): aggregate(self.report(),s)
        s=self.selection(); s['objects']*=65
        with self.assertRaises(ValueError): aggregate(self.report(),s)

    def test_other_generation_not_joined(self):
        s=self.selection(); s['objects'][0]['generation']=9999
        self.assertEqual(aggregate(self.report(),s)['objects'][0]['status'],'NOT_OBSERVED')

    def test_actor_overflow_is_visible(self):
        report=self.report(); report['calls']=[]
        original=self.report()['calls'][0]
        for i in range(9):
            call=copy.deepcopy(original); call['actor'][0]=i+1; report['calls'].append(call)
        out=aggregate(report,self.selection())['objects'][0]
        self.assertEqual(out['status'],'TRUNCATED'); self.assertEqual(len(out['actors']),8)
        self.assertEqual(out['omitted_actor_steps'],1)
