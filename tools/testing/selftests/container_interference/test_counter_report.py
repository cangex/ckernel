# SPDX-License-Identifier: GPL-2.0
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]/'container_interference'))
from counter_report import analyze
from owner_report import fields
import test_prototype
import test_collector_manifest


class CounterReport(unittest.TestCase):
    def record(self):
        row = test_prototype.Explanations().record(); row['collector'] = 'counter'
        row['receipt']['producer_recursion'] = dict(required=True, valid=True, skipped=0)
        row['inventory'] = test_collector_manifest.CollectorContract().inventory('counter')
        return row

    def call(self, actor=1, start=10, leaf=100, parent=200, fail=False):
        sequence = [(1, leaf, 0, 0), (2, leaf, 1, 0), (2, parent, 1, 1)]
        if fail: sequence += [(4, parent, 1, 1), (5, leaf, 0, 0)]
        sequence += [(9, parent if fail else leaf, 0 if fail else 1, 1)]
        result = []
        for ordinal, (stage, obj, usage, depth) in enumerate(sequence):
            fields = dict(protocol=1, sample_time_ns=start+ordinal+1, call_ns=start,
                          tid=101+actor, task_start=1, cpu=0, leaf=leaf, object=obj,
                          parent=parent if obj==leaf else 0, operation=3 if fail else 2,
                          stage=stage, depth=depth, ordinal=ordinal, pages=1, usage=usage,
                          limit_snapshot=0 if fail else 32, sample_shift=0, stack_id=-1)
            result.append(dict(session_id='7', kind='COUNTER', id=actor, generation=1,
                               detail=' '.join('%s=%s'%v for v in fields.items())))
        return result

    def run_rows(self, rows, record=None):
        return analyze(record or self.record(), '\n'.join(json.dumps(r) for r in rows).encode())

    def test_shared_ancestor_not_lock_owner(self):
        r=self.run_rows(self.call()+self.call(actor=2,start=30,leaf=101))
        self.assertEqual(len(r['calls']), 2)
        self.assertEqual([c['address'] for c in r['address_candidates']], [200])
        self.assertTrue(all(c['holder'] is None and not c['same_live_object_proven'] for c in r['address_candidates']))

    def test_independent_counters(self):
        self.assertFalse(self.run_rows(self.call()+self.call(actor=2,start=30,leaf=101,parent=201))['address_candidates'])

    def test_limit_failure_rollback_not_wait(self):
        r=self.run_rows(self.call(fail=True))
        self.assertEqual(r['calls'][0]['failure_address'], 200)
        self.assertEqual(r['calls'][0]['outcome'], 'limit_failed')
        self.assertIsNone(r['calls'][0]['spin_cycles'])

    def test_missing_step_duplicate_and_window_rejected(self):
        rows=self.call(fail=True)
        for broken in (rows[:3]+rows[4:], rows+[rows[2]], self.call(start=99)):
            self.assertFalse(self.run_rows(broken)['calls'])

    def test_partial_and_unknown_actor_rejected(self):
        r=self.record(); r['result']='PARTIAL'
        self.assertFalse(self.run_rows(self.call(), r)['calls'])
        self.assertFalse(self.run_rows(self.call(actor=3))['calls'])

    def test_address_reuse_stays_candidate(self):
        r=self.run_rows(self.call()+self.call(actor=2,start=40))
        self.assertTrue(all(c['object_lifetime']=='UNKNOWN' for c in r['calls']))
        self.assertTrue(all(c['evidence']=='E1' for c in r['address_candidates']))

    def test_fixed_sample_no_population_estimate(self):
        rows=self.call()
        for row in rows: row['detail']=row['detail'].replace('sample_shift=0','sample_shift=6')
        r=self.run_rows(rows)
        self.assertEqual(r['calls'][0]['sample_shift'],6)
        self.assertNotIn('total_cycles',r)

    def version2(self, rows, offset=1000):
        for row in rows:
            d=fields(row['detail']); d['protocol']=2
            for field,address in (('leaf_generation','leaf'),('object_generation','object'),('parent_generation','parent')):
                d[field]=d[address]+offset if d[address] else 0
            row['detail']=' '.join('%s=%s'%item for item in d.items())
        return rows

    def test_initialized_object_participation_not_causal(self):
        r=self.run_rows(self.version2(self.call()+self.call(actor=2,start=30,leaf=101)))
        self.assertFalse(r['address_candidates'])
        self.assertEqual([s['address'] for s in r['shared_objects']],[200])
        self.assertEqual(r['shared_objects'][0]['object_generation'],1200)
        self.assertEqual(r['shared_objects'][0]['evidence'],'E2')
        self.assertEqual(r['shared_objects'][0]['cacheline_contention'],'UNVERIFIED')
        self.assertIsNone(r['shared_objects'][0]['holder'])

    def version3(self, rows):
        for row in self.version2(rows):
            d=fields(row['detail']); d['protocol']=3
            d['owner_cgroup']=90 if d['object']==200 else d['object']+100
            d['resource_kind']=1
            row['detail']=' '.join('%s=%s'%v for v in d.items())
        return rows

    def test_native_resource_owner_is_not_actor_or_holder(self):
        r=self.run_rows(self.version3(self.call()+self.call(actor=2,start=30,leaf=101)))
        obj=r['shared_objects'][0]
        self.assertEqual(obj['owner_cgroup'],90)
        self.assertEqual(obj['resource_kind'],'memory')
        self.assertEqual(obj['provenance'],'NATIVE_IMMUTABLE_BINDING')
        self.assertIsNone(obj['holder'])
        self.assertEqual(obj['cacheline_contention'],'UNVERIFIED')

    def test_native_provenance_corruption_rejected(self):
        for replacement in ('owner_cgroup=0','owner_cgroup=-1','resource_kind=9'):
            rows=self.version3(self.call())
            key=replacement.split('=')[0]
            d=fields(rows[2]['detail']); d[key]=int(replacement.split('=')[1])
            rows[2]['detail']=' '.join('%s=%s'%v for v in d.items())
            self.assertEqual(self.run_rows(rows)['quality']['status'],'FAIL')
        rows=self.version3(self.call()+self.call(actor=2,start=30,leaf=101))
        rows[-2]['detail']=rows[-2]['detail'].replace('owner_cgroup=90','owner_cgroup=91')
        self.assertEqual(self.run_rows(rows)['quality']['status'],'FAIL')

    def test_unannotated_counter_does_not_inherit_actor(self):
        rows=self.version3(self.call()+self.call(actor=2,start=30,leaf=101))
        for row in rows:
            d=fields(row['detail']); d.update(owner_cgroup=0,resource_kind=0)
            row['detail']=' '.join('%s=%s'%v for v in d.items())
        obj=self.run_rows(rows)['shared_objects'][0]
        self.assertIsNone(obj['owner_cgroup'])
        self.assertEqual(obj['provenance'],'UNKNOWN')

    def test_reinitialized_address_not_shared_object(self):
        r=self.run_rows(self.version2(self.call())+self.version2(self.call(actor=2,start=30),offset=2000))
        self.assertEqual(len(r['calls']),2)
        self.assertFalse(r['shared_objects'])
        self.assertFalse(r['address_candidates'])

    def test_generation_corruption_invalidates_stream(self):
        rows=self.version2(self.call())
        rows[2]['detail']=rows[2]['detail'].replace('object_generation=1200','object_generation=-1')
        self.assertEqual(self.run_rows(rows)['quality']['status'],'FAIL')
        rows=self.version2(self.call())
        for row in rows: row['detail']=row['detail'].replace('1200','1100')
        self.assertEqual(self.run_rows(rows)['quality']['status'],'FAIL')

    def test_zero_generation_does_not_get_lifetime(self):
        rows=self.version2(self.call()+self.call(actor=2,start=30))
        for row in rows:
            d=fields(row['detail'])
            for name in ('leaf_generation','object_generation','parent_generation'): d[name]=0
            row['detail']=' '.join('%s=%s'%item for item in d.items())
        r=self.run_rows(rows)
        self.assertFalse(r['shared_objects'])
        self.assertTrue(r['address_candidates'])
        self.assertTrue(all(c['object_lifetime']=='UNKNOWN' for c in r['calls']))

    def test_generation_changes_inside_call_are_not_accepted(self):
        rows=self.version2(self.call())
        rows[2]['detail']=rows[2]['detail'].replace('object_generation=1200','object_generation=2200')
        r=self.run_rows(rows)
        self.assertFalse(r['calls'])
        self.assertEqual(r['excluded']['object_changed_within_call'],1)


if __name__ == '__main__': unittest.main()
