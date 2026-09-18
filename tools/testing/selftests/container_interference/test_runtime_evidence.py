# SPDX-License-Identifier: GPL-2.0
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]/'container_interference'))
from runtime_evidence import analyze, STAGES


class RuntimeEvidence(unittest.TestCase):
    def log(self, inject=True, mismatch=False):
        rows=[]
        for i,stage in enumerate(STAGES):
            rec=dict(session_id=i+1,nonce='stage'+stage.replace('_',''),result='PARTIAL',objects_absent=True,
                     source_identity={'worker_sha256':'b' if mismatch else 'a'})
            rows += ['CIS_FILE /tmp/records/%d.json'%(i+1),json.dumps(rec),
                     'CIS_FILE /tmp/records/%d.jsonl'%(i+1)]
            if inject:
                rows.append(json.dumps(dict(session_id=i+1,kind='fault_injection',detail='stage='+stage+' errno=12')))
        rows += ['CIS_FILE /tmp/trailer.txt','CIS_PROFILE_VM_EXIT=0']
        return '\n'.join(rows)

    def test_raw_faults_prove_only_subclaim(self):
        result=analyze(self.log(),{'worker_sha256':'a'})
        self.assertEqual(result['subchecks']['boundary_failures']['status'],'PASS')
        self.assertEqual(result['subchecks']['real_fd_exhaustion']['status'],'BLOCKED')
        self.assertFalse(result['full_resource_failures_complete'])

    def test_partial_label_without_injection_is_not_proof(self):
        result=analyze(self.log(inject=False),{'worker_sha256':'a'})
        self.assertEqual(result['subchecks']['boundary_failures']['status'],'FAIL')

    def test_source_and_exit(self):
        with self.assertRaises(ValueError):analyze(self.log(mismatch=True),{'worker_sha256':'a'})
        result=analyze(self.log()+'\nCIS_PROFILE_VM_EXIT=1',{'worker_sha256':'a'})
        self.assertEqual(result['subchecks']['boundary_failures']['status'],'FAIL')

    def test_duplicate_artifact_cannot_overwrite_failure(self):
        with self.assertRaises(ValueError):
            analyze(self.log()+'\nCIS_FILE /tmp/records/1.json\n{}',{'worker_sha256':'a'})

    def test_fd_limit_needs_readback_not_only_partial_label(self):
        rows=[]
        for value in range(4,25):
            rec=dict(session_id=value,nonce='fdLimit%d'%value,result='PARTIAL',objects_absent=True,
                     receipt={'reason':'PREPARE'},source_identity={'worker_sha256':'a'})
            rows += ['CIS_FILE /tmp/records/%d.json'%value,json.dumps(rec),
                     'CIS_FILE /tmp/records/%d.jsonl'%value,
                     json.dumps(dict(session_id=value,kind='fault_injection',detail='stage=fd_limit requested=%d soft=%d hard=%d'%(value,value,value)))]
        text='\n'.join(rows+['CIS_FILE /tmp/trailer.txt','CIS_PROFILE_VM_EXIT=0'])
        self.assertEqual(analyze(text,{'worker_sha256':'a'})['subchecks']['real_fd_exhaustion']['status'],'PASS')
        self.assertEqual(analyze(text.replace('soft=4 ','soft=99 ',1),{'worker_sha256':'a'})['subchecks']['real_fd_exhaustion']['status'],'FAIL')

    def test_inventory_restore_checks_raw_ids(self):
        audit=dict(before={'maps':[],'programs':[]},checks=[dict(nonce='stage'+stage.replace('_',''),session_id=i+1,
                   time_ns=i+1,after={'maps':[],'programs':[]}) for i,stage in enumerate(STAGES)])
        text=self.log()+'\nCIS_FILE /tmp/resource-inventories.json\n'+json.dumps(audit)
        self.assertEqual(analyze(text,{'worker_sha256':'a'})['subchecks']['inventory_restoration']['status'],'BLOCKED')
        audit['checks'][0]['after']['maps']=[99]
        text=self.log()+'\nCIS_FILE /tmp/resource-inventories.json\n'+json.dumps(audit)
        self.assertEqual(analyze(text,{'worker_sha256':'a'})['subchecks']['inventory_restoration']['status'],'FAIL')
        audit['before']={}
        with self.assertRaises(ValueError):analyze(self.log()+'\nCIS_FILE /tmp/resource-inventories.json\n'+json.dumps(audit),{'worker_sha256':'a'})


if __name__=='__main__':unittest.main()
