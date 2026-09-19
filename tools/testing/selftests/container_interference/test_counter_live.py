# SPDX-License-Identifier: GPL-2.0
import copy
import json
import unittest

from counter_live import analyze
from owner_report import fields
import test_counter_report


class CounterLive(unittest.TestCase):
    def input(self):
        helper=test_counter_report.CounterReport(); record=helper.record(); record['selected_objects']=[200]
        rows=helper.version2(helper.call()+helper.call(actor=2,start=30,leaf=101))
        rows.append(dict(kind='counter_selection',detail='index=0 count=1 object=200 readback=1'))
        rows.append(dict(kind='counter_sum_audit',detail='objects=1 targets=2 buckets=12 possible_cpus=8 producers_detached=1'))
        for actor in (1,2):
            samples=[fields(r['detail']) for r in rows if r['kind']=='COUNTER' and r['id']==actor
                     and fields(r['detail'])['object']==200 and 2<=fields(r['detail'])['stage']<=8]
            d=dict(protocol=1,object=200,object_generation=1200,operation=2,
                   first_ns=min(s['sample_time_ns'] for s in samples),last_ns=max(s['sample_time_ns'] for s in samples),
                   sample_shift=0,tainted=0,min_depth=1,max_depth=1,producers_detached=1)
            for i in range(2,9):
                d['n'+str(i)]=sum(s['stage']==i for s in samples)
                d['q'+str(i)]=sum(s['pages'] for s in samples if s['stage']==i)
            for i in range(8): d['h'+str(i)]=len(samples) if not i else 0
            rows.append(dict(kind='counter_sum',id=actor,generation=1,detail=' '.join('%s=%s'%v for v in d.items())))
        return record,rows

    def run_rows(self,record,rows,quality='PASS'):
        return analyze(record,'\n'.join(json.dumps(r) for r in rows).encode(),dict(status=quality))

    def test_independent_event_reconciliation(self):
        record,rows=self.input(); r=self.run_rows(record,rows)
        self.assertEqual(r['status'],'PASS'); self.assertEqual(len(r['objects']),2)
        self.assertEqual(len(r['shared_objects']),1)
        self.assertIsNone(r['shared_objects'][0]['holder'])
        self.assertEqual(r['cacheline_contention'],'UNVERIFIED')

    def test_missing_terminal_selection_or_bucket_rejected(self):
        record,rows=self.input()
        for kind in ('counter_selection','counter_sum_audit','counter_sum'):
            result=self.run_rows(record,[r for r in rows if r['kind']!=kind])
            self.assertEqual(result['status'],'FAIL'); self.assertFalse(result['shared_objects'])

    def test_corruption_duplicate_or_unknown_participant_rejected(self):
        record,rows=self.input()
        for suffix in ('n2=2','q2=2','h0=2','object_generation=2200','producers_detached=0'):
            changed=copy.deepcopy(rows); changed[-1]['detail']+=' '+suffix
            self.assertEqual(self.run_rows(record,changed)['status'],'FAIL')
        self.assertEqual(self.run_rows(record,rows+[rows[-1]])['status'],'FAIL')
        changed=copy.deepcopy(rows); changed[-1]['id']=999
        self.assertEqual(self.run_rows(record,changed)['status'],'FAIL')

    def test_address_reuse_is_downgraded_not_shared(self):
        record,rows=self.input(); rows[-1]['detail']+=' tainted=1'
        r=self.run_rows(record,rows)
        self.assertEqual(r['status'],'PASS'); self.assertFalse(r['shared_objects'])
        self.assertEqual(r['objects'][-1]['evidence'],'E1')

    def test_failed_quality_never_gets_e2(self):
        record,rows=self.input(); r=self.run_rows(record,rows,'FAIL')
        self.assertEqual(r['status'],'FAIL'); self.assertFalse(r['shared_objects'])
        self.assertTrue(all(v['evidence']=='UNACCEPTED' for v in r['objects']))

    def test_aggregate_does_not_accept_pre_window_sample(self):
        record,rows=self.input()
        record['window']['start_ns']=1
        for row in rows:
            if row['kind']=='COUNTER' and 'object=200 ' in row['detail']:
                row['detail']+=' call_ns=0'
        result=self.run_rows(record,rows)
        self.assertEqual(result['status'],'FAIL')
        self.assertIn('sample_identity_or_window',result['defects'])

    def test_old_unspecified_capture_is_readable(self):
        self.assertEqual(analyze({},b'',{})['status'],'NOT_REQUESTED')
