# SPDX-License-Identifier: GPL-2.0
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]/'container_interference'))
from sync_report import analyze
import test_prototype
import test_collector_manifest


class SyncCandidates(unittest.TestCase):
    def record(self):
        row=test_prototype.Explanations().record(); row['collector']='sync'
        row['receipt']['producer_recursion']=dict(required=True,valid=True,skipped=0)
        row['inventory']=test_collector_manifest.CollectorContract().inventory('sync')
        return row

    def raw(self, flags=1, time=10, duration=20, object=123, id=1):
        return json.dumps(dict(session_id='7',kind='E1',id=id,generation=1,
            detail='type=3 sample_time_ns=%d duration_ns=%d flags=%d object=%d tid=101 stack_id=-1'%(time,duration,flags,object))).encode()

    def test_spin_read_write_are_candidates_not_owners(self):
        for flags, access in [(1,'spin'),(2,'read'),(4,'write')]:
            result=analyze(self.record(),self.raw(flags=flags))
            candidate=result['candidates'][0]
            self.assertEqual(candidate['access_class'],access)
            self.assertEqual(candidate['evidence'],'E1')
            self.assertIsNone(candidate['holder'])
            self.assertEqual(result['coverage']['owner'],'NOT_IMPLEMENTED')

    def test_reuse_cannot_create_cross_container_relation(self):
        raw=self.raw()+b'\n'+self.raw(time=40,id=2)
        result=analyze(self.record(),raw)
        self.assertEqual(len(result['candidates']),2)
        self.assertTrue(all(x['object_lifetime']=='UNKNOWN' and x['holder'] is None for x in result['candidates']))

    def test_unknown_context_incomplete_and_loss(self):
        for flags in (8,16,128):
            self.assertFalse(analyze(self.record(),self.raw(flags=flags))['candidates'])
        self.assertFalse(analyze(self.record(),self.raw(time=90,duration=20))['candidates'])
        row=self.record(); row['receipt']['terminal']['lost']=1
        self.assertFalse(analyze(row,self.raw())['candidates'])
        result=analyze(self.record(),self.raw(flags=0x80000004))
        self.assertEqual(result['candidates'][0]['outcome'],'aborted_or_failed')


if __name__=='__main__': unittest.main()
