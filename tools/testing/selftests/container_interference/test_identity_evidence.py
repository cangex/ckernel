# SPDX-License-Identifier: GPL-2.0
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'container_interference'))
from identity_evidence import analyze


class IdentityEvidence(unittest.TestCase):
    def files(self):
        report=dict(session_id='7',previous_registration='1:2',previous_b='3:4',recreated_registration='5:6',
                    moved_begin_ns=3_000_000,moved_end_ns=3_100_000,boundary_margin_ns=1_000_000,migrated_pids=['9'],
                    migration=dict(before_a=16,after_b=16,ambiguous_boundary=0))
        requests=[('register',{},dict(ok=True,data=dict(target='1:2'))),
                  ('register',{},dict(ok=True,data=dict(target='3:4'))),
                  ('register',{},dict(ok=False,error='overlap')),
                  ('start',dict(nonce='deletedRoot',targets=['1:2']),dict(ok=False,error='target deleted or renamed')),
                  ('unregister',dict(target='1:2'),dict(ok=True,data={})),
                  ('register',{},dict(ok=True,data=dict(target='5:6')))]
        actions=[dict(sequence=i+1,before_ns=i*2,after_ns=i*2+1,request=dict(op=op,**fields),response=r) for i,(op,fields,r) in enumerate(requests)]
        events=[dict(session_id='7',kind='IP',id=1 if i<16 else 3,generation=2 if i<16 else 4,detail='sample_time_ns=%d'%(1_000_000 if i<16 else 5_000_000)) for i in range(32)]
        record=dict(session_id='7',targets=['1:2','3:4'],source_identity=dict(worker_sha256='a'))
        return {'/tmp/identity-result.json':json.dumps(report), '/tmp/identity-requests.jsonl':'\n'.join(map(json.dumps,actions)),
                '/tmp/identity-records/7.json':json.dumps(record),'/tmp/identity-records/7.jsonl':'\n'.join(map(json.dumps,events))}

    @patch('identity_evidence.assess',return_value={'status':'PASS'})
    def test_raw_matches_not_universal_identity(self,_):
        result=analyze(self.files(),dict(worker_sha256='a'))
        self.assertEqual(result['status'],'PASS')
        self.assertFalse(result['full_identity_complete'])

    @patch('identity_evidence.assess',return_value={'status':'PASS'})
    def test_wrong_container_rejected(self,_):
        files=self.files();files['/tmp/identity-records/7.jsonl']=files['/tmp/identity-records/7.jsonl'].replace('"id": 1','"id": 3',1)
        self.assertEqual(analyze(files,dict(worker_sha256='a'))['status'],'FAIL')

    @patch('identity_evidence.assess',return_value={'status':'PASS'})
    def test_summary_or_source_mismatch(self,_):
        for path,old,new in [('/tmp/identity-result.json','"before_a": 16','"before_a": 17'),
                              ('/tmp/identity-records/7.json','"worker_sha256": "a"','"worker_sha256": "b"'),
                              ('/tmp/identity-requests.jsonl','"sequence": 1','"sequence": 9')]:
            files=self.files();files[path]=files[path].replace(old,new,1)
            with self.assertRaises(ValueError):analyze(files,dict(worker_sha256='a'))

    def test_missing_transcript_or_incomplete_capture(self):
        self.assertEqual(analyze({},dict(worker_sha256='a'))['status'],'BLOCKED')
        with patch('identity_evidence.assess',return_value={'status':'BLOCKED'}):
            self.assertEqual(analyze(self.files(),dict(worker_sha256='a'))['status'],'FAIL')


if __name__=='__main__':unittest.main()
