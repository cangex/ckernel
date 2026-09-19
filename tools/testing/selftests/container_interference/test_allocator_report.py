# SPDX-License-Identifier: GPL-2.0
import json
import unittest
import test_counter_report
import test_collector_manifest
from allocator_report import analyze


class AllocatorReport(unittest.TestCase):
    def record(self):
        r=test_counter_report.CounterReport().record(); r['collector']='allocator'
        r['inventory']=test_collector_manifest.CollectorContract().inventory('allocator')
        return r

    def rows(self, sequence=None, bulk=False, fail=False):
        seq=sequence or [1,2,3,4,8,10,11,12,9,13,14,5,15,16,20]
        rows=[]
        for i,stage in enumerate(seq):
            d=dict(protocol=1,sample_time_ns=11+i,call_ns=10,tid=102,task_start=1,cpu=0,
                cache=100,object=0 if fail else 500,resource=200 if stage in (10,11,12) else 0,
                operation=2 if bulk else 1,stage=stage,ordinal=i,gfp=64,requested=4 if bulk else 1,
                count=2 if stage==18 else 0 if fail else 4 if bulk else 1,
                requested_node=-1,observed_node=-1,sample_shift=6,stack_id=-1)
            rows.append(dict(session_id='7',kind='ALLOCATOR',id=1,generation=1,
                             detail=' '.join('%s=%s'%item for item in d.items())))
        return rows

    def run_rows(self,rows,record=None):
        return analyze(record or self.record(),'\n'.join(json.dumps(r) for r in rows).encode())

    def test_nested_partition_not_double_counted(self):
        c=self.run_rows(self.rows())['calls'][0]
        self.assertEqual(sum(c['exclusive_wall_ns'].values()),c['elapsed_wall_ns'])
        self.assertGreater(sum(p['end_ns']-p['begin_ns'] for p in c['phases']),c['elapsed_wall_ns'])
        self.assertIsNone(c['holder']); self.assertIsNone(c['spin_cycles'])
        self.assertEqual(c['cache_lifetime'],'UNKNOWN'); self.assertEqual(c['observed_nodes'],[])

    def test_failed_bulk_retains_prefix_rollback(self):
        c=self.run_rows(self.rows([1,2,3,4,5,18,15,16,20],bulk=True,fail=True))['calls'][0]
        self.assertEqual(c['returned_count'],0); self.assertEqual(c['rolled_back_count'],2)
        self.assertEqual(c['result'],dict(status='FAILED',failure_region='bulk_rollback',cause='UNKNOWN'))

    def test_failure_region_does_not_invent_root_cause(self):
        c=self.run_rows(self.rows([1,2,3,20],fail=True))['calls'][0]
        self.assertEqual(c['result'],dict(status='FAILED',failure_region='pre_allocation_hook',cause='UNKNOWN'))
        c=self.run_rows(self.rows([1,2,3,4,13,14,5,15,16,20],fail=True))['calls'][0]
        self.assertEqual(c['result'],dict(status='FAILED',failure_region='backend_or_post_hook',cause='UNKNOWN'))
        c=self.run_rows(self.rows())['calls'][0]
        self.assertEqual(c['result'],dict(status='RETURNED',failure_region=None,cause=None))

    def test_missing_ends_and_changed_resource_rejected(self):
        for sequence in ([1,2,20],[1,2,3,4,20],[1,2,3,12,20]):
            self.assertFalse(self.run_rows(self.rows(sequence))['calls'])
        rows=self.rows(); rows[7]['detail']=rows[7]['detail'].replace('resource=200','resource=201')
        self.assertFalse(self.run_rows(rows)['calls'])

    def test_loss_partial_and_malformed_cannot_certify(self):
        rows=self.rows(); rows[3]['detail']=rows[3]['detail'].replace('protocol=1','protocol=2')
        self.assertEqual(self.run_rows(rows)['quality']['status'],'FAIL')
        rows=self.rows(); self.assertFalse(self.run_rows(rows[:5]+rows[6:])['calls'])
        r=self.record(); r['result']='PARTIAL'
        self.assertFalse(self.run_rows(self.rows(),r)['calls'])

    def test_unknown_or_unobserved_owner_not_guessed(self):
        c=self.run_rows(self.rows([1,2,3,6,15,16,20]))['calls'][0]
        self.assertEqual(c['free_owner'],'UNOBSERVED')
        rows=self.rows()
        for row in rows: row['id']=55
        self.assertFalse(self.run_rows(rows)['calls'])
