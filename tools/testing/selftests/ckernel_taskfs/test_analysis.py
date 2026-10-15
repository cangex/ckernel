# SPDX-License-Identifier: GPL-2.0
import copy
import unittest
from analyze import analyze
from template import validate_geometry


class AnalysisTests(unittest.TestCase):
    def bundle(self):
        row=dict(status='PASS',condition='S',n=1,request_ns=0,setup_end_ns=2,grading_begin_ns=10,
            grading_end_ns=12,retention_and_cleanup_begin_ns=13,turnover_end_ns=20,
            business=dict(status='PASS',instances=[dict(slot=0,start_ns=4,end_ns=6,elapsed_s=2e-9,official_grade='PASS',exit_code=0)]),
            cost_window=dict(before_end_ns=3,completion_ack_ns=7,end_snapshot_begin_ns=8,end_snapshot_end_ns=9))
        rows=[]
        for arm in 'SGFB':
            for index in range(3):
                item=copy.deepcopy(row);item['condition']=arm;item['business']['name']=f'{arm}-{index}';rows.append(item)
        fields={'Block count':'196608','Block size':'4096','Inode count':'32832','Total journal blocks':'4096'}
        return dict(summary=dict(status='PASS'),states=rows,
            objects=[dict(id='a',thin_id=1,state='DELETED',spec=dict(bytes=768*1024**2,inodes=32832,journal_mib=16))],
            geometry_observations=[dict(identity='a',observed=fields)])

    def test_accept_boundaries_not_performance(self):
        result=analyze(self.bundle());self.assertEqual(result['copies'],12)
        self.assertEqual(result['net_benefit'],'NOT_ESTABLISHED')

    def test_early_end_rejected(self):
        b=self.bundle();b['states'][0]['cost_window']['end_snapshot_begin_ns']=5
        with self.assertRaises(ValueError):analyze(b)

    def test_missing_or_failed_rejected(self):
        b=self.bundle();b['states'].pop()
        with self.assertRaises(ValueError):analyze(b)
        b=self.bundle();b['states'][0]['business']['instances'][0]['official_grade']='FAIL'
        with self.assertRaises(ValueError):analyze(b)

    def test_actual_geometry_rejected(self):
        b=self.bundle();b['geometry_observations'][0]['observed']['Inode count']='32768'
        with self.assertRaises(RuntimeError):analyze(b)

    def test_identity_reuse_rejected(self):
        b=self.bundle();obj=copy.deepcopy(b['objects'][0]);obj['id']='b';b['objects'].append(obj)
        op=copy.deepcopy(b['geometry_observations'][0]);op['identity']='b';b['geometry_observations'].append(op)
        with self.assertRaises(ValueError):analyze(b)
