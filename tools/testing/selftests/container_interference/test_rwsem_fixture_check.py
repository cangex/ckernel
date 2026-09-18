# SPDX-License-Identifier: GPL-2.0
import copy
import unittest
from rwsem_fixture_check import check, truth


class NativeOracle(unittest.TestCase):
    def evidence(self):
        def line(**kw):
            v=dict(reset=0,slot=0,token=1,object=16,task=101,mode=1,hold_ms=200,
                   enter_ns=2_000_000,acquired_ns=3_000_000,release_ns=10_000_000,end_ns=11_000_000,outcome=1)
            v.update(kw); return 'CIS_RWSEM_TRUTH '+' '.join('%s=%s'%x for x in v.items())
        logs=dict(reset=line(reset=1,mode=0,hold_ms=0,enter_ns=1,acquired_ns=0,release_ns=0,end_ns=100,outcome=0),
            holder=line(),waiter=line(task=102,mode=0,hold_ms=0,enter_ns=4_000_000,
                acquired_ns=12_000_000,release_ns=15_000_000,end_ns=16_000_000))
        jobs=[dict(log='reset',actor_index=0,token=1,arguments=dict(reset=True)),
              dict(log='holder',actor_index=0,token=1,arguments=dict(mode=1,hold=200)),
              dict(log='waiter',actor_index=1,token=1,arguments={})]
        report=dict(quality=dict(status='PASS'),scope_audit=dict(status='PASS'),objects=[
            dict(address=16,init_ns=50,waits=[dict(waiter=[2,1,102,100],observed_holders=[
                dict(holder=[1,1,101,100],mode='write',evidence='E2',interval_ns=[4_000_000,10_000_000])])])])
        return report,jobs,logs,[dict(id=1,generation=1),dict(id=2,generation=1)],'writeRead',dict(start_ns=0,end_ns=20_000_000)

    def test_complete_true_relation(self):
        result=check(*self.evidence())
        self.assertEqual(result['status'],'PASS',result)
        self.assertEqual((result['eligible'],result['captured_eligible']),(1,1))

    def test_wrong_identity_reuse_and_interval_rejected(self):
        for change in ('container','token','holder','interval'):
            args=list(copy.deepcopy(self.evidence())); pair=args[0]['objects'][0]['waits'][0]['observed_holders'][0]
            if change=='container': pair['holder'][0]=3
            elif change=='token': args[0]['objects'][0]['init_ns']=500
            elif change=='holder': pair['holder'][2]=103
            else: pair['interval_ns'][1]=19_000_000
            self.assertEqual(check(*args)['status'],'FAIL',change)

    def test_negative_case_and_missing_capture_rejected(self):
        args=list(self.evidence()); args[4]='private'
        self.assertIn('negative_case_promoted',check(*args)['errors'])
        args=list(self.evidence()); args[0]['objects'][0]['waits'][0]['observed_holders']=[]
        self.assertIn('eligible_recall',check(*args)['errors'])

    def test_truth_cannot_claim_failed_hold_or_missing_timestamp(self):
        args=self.evidence(); line=args[2]['holder']
        for bad in (line.replace('outcome=1','outcome=0'),line.replace('enter_ns=2000000','enter_ns=0'),line+'\n'+line):
            with self.assertRaises(ValueError): truth(bad)


if __name__=='__main__': unittest.main()
