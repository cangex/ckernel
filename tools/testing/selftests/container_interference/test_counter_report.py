# SPDX-License-Identifier: GPL-2.0
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]/'container_interference'))
from counter_report import analyze
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


if __name__ == '__main__': unittest.main()
