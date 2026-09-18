# SPDX-License-Identifier: GPL-2.0
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]/'container_interference'))
from prototype_admission import SOURCE_KEYS
from x0_check import check


class X0RawCheck(unittest.TestCase):
    def serial(self, expired=True, complete=True, source_present=True):
        source = {key:'a'*64 for key in SOURCE_KEYS} if source_present else {}
        end = 1200*10**9+1
        requests=[]
        for i, op in enumerate(('schedule_enable','start')):
            requests.append(dict(sequence=i+1,before_ns=(end+10*i if expired else 2+10*i),
                after_ns=(end+10*i+1 if expired else 3+10*i),request=dict(op=op),response=dict(ok=False)))
        base='/tmp/prototype-evidence/'
        values={'plan.json':dict(schema='cis-x0-plan-v1',expiry=True,fault=False,source=source),
                'result.json':dict(schema='cis-x0-result-v1',source=source,
                    checks=[dict(name='real_permit_expiry',status='PASS')]),
                'permit.json':dict(source=source,created_ns=1,expires_ns=end)}
        text='CIS_PROFILE_VM_EXIT=0\n'
        text+=''.join('CIS_FILE '+base+name+'\n'+json.dumps(value)+'\n' for name,value in values.items())
        text+='CIS_FILE '+base+'requests.jsonl\n'
        text+='\n'.join(json.dumps(row) for row in (requests if complete else requests[:1]))+'\n'
        return text

    def test_requires_actual_expired_request_and_complete_audit(self):
        self.assertEqual(check(self.serial())['status'],'PASS')
        self.assertEqual(check(self.serial(expired=False))['status'],'FAIL')
        self.assertEqual(check(self.serial(complete=False))['status'],'FAIL')

    def test_pass_word_not_enough(self):
        with self.assertRaises(ValueError): check(self.serial(source_present=False))
        self.assertEqual(check(self.serial().replace('CIS_PROFILE_VM_EXIT=0','CIS_PROFILE_VM_EXIT=1'))['status'],'FAIL')


if __name__=='__main__': unittest.main()
