# SPDX-License-Identifier: GPL-2.0
import json
import unittest
from unittest.mock import patch

from net_capacity_check import check


class NetCapacity(unittest.TestCase):
    def sample(self):
        window=dict(start_ns=10,end_ns=1000); logs=[]
        for actor in range(2):
            rows=['CIS_NET_CAPACITY actor=%d index=%d cookie=%d begin_ns=%d end_ns=%d'%
                  (actor,i,1+actor*40+i,20+i,21+i) for i in range(40)]
            rows.append('CIS_NET_CAPACITY_AFTER actor=%d operations=40 errors=0 begin_ns=1200 end_ns=1300'%actor)
            logs.append('\n'.join(rows))
        record=dict(collector='net',finalized=True,objects_absent=True,state='IDLE')
        quality=dict(status='FAIL',defects=['terminal.rejected'],terminal=dict(valid=True,rejected=16),budget_abort=False)
        report=dict(quality=quality,relations=[],specialist=dict(sockets=[]))
        raw=('\n'.join(json.dumps(dict(kind='NET',detail='cookie=%d'%i)) for i in range(1,65))+'\n').encode()
        return window,logs,record,raw,dict(after_ns=1100),report

    def test_map_full_is_rejected_observation_and_successful_protection(self):
        *args,report=self.sample()
        with patch('net_capacity_check.analyze',return_value=report):
            result=check(*args)
        self.assertEqual(result['status'],'PASS',result)
        self.assertEqual(result['quality']['status'],'FAIL')
        self.assertEqual(result['native_cookies'],80)

    def test_no_attribution_is_accepted_from_capacity_truncation(self):
        for mutation in ('quality','relation','socket','capacity','budget','cleanup','counter'):
            *args,report=self.sample()
            if mutation=='quality': report['quality']['status']='PASS'
            elif mutation=='relation': report['relations']=[dict(evidence='E2')]
            elif mutation=='socket': report['specialist']['sockets']=[dict(cookie=1)]
            elif mutation=='capacity': args[3]=args[3].replace(b'cookie=64',b'cookie=1')
            elif mutation=='budget': report['quality']['budget_abort']=True
            elif mutation=='cleanup': args[2]['objects_absent']=False
            else: report['quality']['terminal']['rejected']=0
            with self.subTest(mutation=mutation),patch('net_capacity_check.analyze',return_value=report):
                self.assertEqual(check(*args)['status'],'FAIL')

    def test_native_population_and_post_detach_continuation_are_required(self):
        for mutation in ('missing','cookie','early','failure'):
            window,logs,_,_,idle,_=self.sample()
            if mutation=='missing': logs[0]=logs[0].replace('CIS_NET_CAPACITY actor=0 index=0','IGNORED actor=0 index=0')
            elif mutation=='cookie': logs[1]=logs[1].replace('cookie=41','cookie=1')
            elif mutation=='early': idle['after_ns']=1250
            else: logs[0]=logs[0].replace('operations=40 errors=0','operations=40 errors=1')
            with self.subTest(mutation=mutation): self.assertEqual(check(window,logs,idle=idle)['status'],'FAIL')

    def test_off_business_does_not_need_fake_capture(self):
        window,logs,_,_,idle,_=self.sample()
        result=check(window,logs,idle=idle)
        self.assertEqual(result['status'],'PASS');self.assertIsNone(result['quality'])


if __name__=='__main__': unittest.main()
