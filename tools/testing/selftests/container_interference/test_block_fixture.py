# SPDX-License-Identifier: GPL-2.0
import unittest
from block_fixture_check import case_order,check_case


class BlockFixture(unittest.TestCase):
    def logs(self,private=False):
        result=[]
        for role in range(2):
            rows=['CIS_SESSION_CONTAINER host_pid=%d'%(101+role),
                'CIS_BLOCK_BEGIN role=%d major=8 minor=%d start_ns=10'%(role,16 if private and role else 0)]
            for n in range(8):
                rows.append('CIS_BLOCK_IO role=%d iteration=%d op=%s offset=%d before_ns=%d after_ns=%d bytes=4096 verified=1'%(
                    role,n//2,('write','read')[n%2],(1+role*8+n//2)*4096,10+n*10,15+n*10))
            rows.append('CIS_BLOCK_DONE operations=8 errors=0'); result.append('\n'.join(rows))
        return result

    def test_frozen_alternation(self):
        rows=case_order(); self.assertEqual(len(rows),12)
        self.assertEqual(rows[:2],['shared-off-r1','shared-block-r1'])
        self.assertEqual(rows[4:6],['shared-block-r2','shared-off-r2'])

    def test_device_selection_and_failed_io(self):
        window=dict(start_ns=0,end_ns=100)
        self.assertEqual(check_case('shared',window,self.logs())['status'],'PASS')
        self.assertEqual(check_case('private',window,self.logs(True))['status'],'PASS')
        self.assertEqual(check_case('private',window,self.logs())['status'],'FAIL')
        logs=self.logs(); logs[0]=logs[0].replace('verified=1','verified=0',1)
        self.assertEqual(check_case('shared',window,logs)['status'],'FAIL')

    def test_zero_coverage_cannot_pass(self):
        report=dict(quality=dict(status='PASS'),scope_audit=dict(status='PASS'),requests=[])
        result=check_case('shared',dict(start_ns=0,end_ns=100),self.logs(),report,
            [dict(id=1,generation=1),dict(id=2,generation=1)])
        self.assertEqual(result['status'],'FAIL')
