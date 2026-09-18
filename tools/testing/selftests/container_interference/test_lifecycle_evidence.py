# SPDX-License-Identifier: GPL-2.0
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'container_interference'))
from lifecycle_evidence import analyze,CASES


class LifecycleEvidence(unittest.TestCase):
    def fixture(self):
        actions=[];records={};time=0
        def append(**value):
            nonlocal time
            time+=10
            actions.append(dict(sequence=len(actions)+1,before_ns=time,after_ns=time+1,**value))
        for i,(nonce,expected) in enumerate(CASES.items(),1):
            sid=str(i)
            record=dict(session_id=sid,nonce=nonce,worker_pid=100+i,worker_start_ticks='9',state='IDLE',objects_absent=True,finalized=True)
            append(kind='request',request=dict(op='status',session=sid),response=dict(ok=True,data=dict(window={'start_ns':10})))
            for role,sig in expected:
                if sig==18:time+=2_500_000_000
                append(kind='signal',role=role,signal=sig,pid=100+i if role=='worker' else 90,start_ticks=9,syscall_result=0,session_id=sid)
            record['result']='COMPLETE' if nonce=='controllerStop' else 'FAILED'
            if nonce not in ('workerCrash','controllerStop'):
                record['recovery']='administrator_checked_pid_absent_and_inventory_absent'
                append(kind='request',request=dict(op='status'),response=dict(ok=True,data=dict(state='FAULTED')))
                append(kind='request',request=dict(op='recover'),response=dict(ok=True,data=dict(record)))
            records[sid]=record
        return {'/tmp/fault-actions.jsonl':'\n'.join(map(json.dumps,actions))},records

    def test_actual_actions_not_marker(self):
        files,records=self.fixture()
        result=analyze(files,records,True)
        self.assertEqual(result['status'],'PASS')
        self.assertFalse(result['full_lifecycle_complete'])
        self.assertEqual(analyze({},records,True)['status'],'BLOCKED')

    def test_wrong_worker_lifetime(self):
        files,records=self.fixture();records['1']['worker_start_ticks']='10'
        self.assertEqual(analyze(files,records,True)['cases']['workerCrash']['status'],'FAIL')

    def test_pause_and_recovery_must_exist(self):
        files,records=self.fixture()
        files['/tmp/fault-actions.jsonl']=files['/tmp/fault-actions.jsonl'].replace('"signal": 19','"signal": 9')
        self.assertEqual(analyze(files,records,True)['status'],'FAIL')
        files,records=self.fixture();del records['2']['recovery']
        self.assertEqual(analyze(files,records,True)['cases']['workerStop']['status'],'FAIL')

    def test_failed_vm_and_duplicate_sequence(self):
        files,records=self.fixture()
        self.assertEqual(analyze(files,records,False)['status'],'FAIL')
        files['/tmp/fault-actions.jsonl']=files['/tmp/fault-actions.jsonl'].replace('"sequence": 2','"sequence": 1',1)
        with self.assertRaises(ValueError):analyze(files,records,True)


if __name__=='__main__':unittest.main()
