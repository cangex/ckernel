# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'container_interference'))
from prototype_check import exploratory_cost, protocol_complete


class PrototypeCost(unittest.TestCase):
    def data(self):
        files={};items=[]
        for repetition in range(3):
            for mode in ('off','ip','owner','sched','reclaim'):
                label='%s%d'%(mode,repetition)
                items.append(dict(workload='throughput',repetition=repetition,mode=mode,label=label))
                for role in range(2):
                    files['/tmp/prototype-evidence/%s-%d.log'%(label,role)]=(
                        'CIS_RESULT operations=%d start_ns=100 end_ns=200 errors=0'% (1000 if mode=='off' else 990))
        return files,dict(measurements=items,plan=dict(workloads=['throughput']))

    def test_records_cost_without_certifying(self):
        files,declared=self.data()
        rows=exploratory_cost(files,declared)
        self.assertEqual(len(rows),8)
        for row in rows:
            self.assertAlmostEqual(row['mean_pct'],1)
            self.assertFalse(row['certified'])
            self.assertEqual(row['status'],'RECORD_ONLY')

    def test_missing_pair_and_bad_denominator_cannot_disappear(self):
        files,declared=self.data()
        key=next(iter(files))
        del files[key]
        with self.assertRaises(ValueError):exploratory_cost(files,declared)
        files,declared=self.data()
        files[key]=files[key].replace('operations=1000','operations=0')
        with self.assertRaises(ValueError):exploratory_cost(files,declared)

    def test_duplicate_measurements_rejected(self):
        files,declared=self.data()
        declared['measurements'].append(declared['measurements'][0])
        with self.assertRaises(ValueError):exploratory_cost(files,declared)

    def test_incomplete_declared_matrix_is_not_a_pass(self):
        sessions=[dict(session_id=str(i),nonce='case%d'%i) for i in range(12)]
        declared=dict(measurements=[],cases=sessions,plan=dict(pairs=3,workloads=['throughput']))
        costs=[dict(n=3,status='RECORD_ONLY') for _ in range(8)]
        self.assertTrue(protocol_complete(declared,sessions,costs))
        self.assertFalse(protocol_complete(declared,sessions[:-1],costs))
        self.assertFalse(protocol_complete(declared,sessions,[dict(n=2,status='INCOMPLETE')]))
