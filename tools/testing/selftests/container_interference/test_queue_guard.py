# SPDX-License-Identifier: GPL-2.0
import copy
import json
import unittest
from unittest.mock import patch
from source_switches import expected_fields
from y5_queue_check import native_totals,source_delta
from y5_queue_guard import check


def native(n):
    return 'version=1 enabled=0 lease_active=0 sample_shift=4 bytes_per_cpu=72\ncpu=0 entries=%d filtered=0 sampled=%d emitted=%d expired=0 recursive=0\n'%(n,n//16,n//16)


class QueueGuard(unittest.TestCase):
    def data(self,on=True):
        def observed(c,t):
            return dict(expected_collector=c,before_ns=t,after_ns=t+1,observed=expected_fields('19',c))
        e=dict(before=dict(native=native(0)),after=dict(native=native(30000 if on else 0)),
            detached=dict(native=native(30000 if on else 0),after_ns=105),
            active_sources=observed('qdisc' if on else None,10),idle_sources=observed(None,110))
        logs=['\n'.join('CIS_QUEUE_BUCKET actor=%d bucket=%d operations=1000 errors=0 begin_ns=%d end_ns=%d'%
                       (i,b,100+b*10,109+b*10) for b in range(8)) for i in range(2)]
        r=dict(collector='qdisc',requested_ns=1,window=dict(start_ns=5,end_ns=90),result='PARTIAL',
            objects_absent=True,finalized=True,state='IDLE',receipt=dict(reason='ENTRY_RATE_LIMIT',stop_error=0))
        raw=json.dumps(dict(kind='entry_budget_disable',detail='configured_limit=200000 delta_entries=30000 interval_ns=100000000 source=qdisc_native detaching_collectors=1')).encode()
        return r,raw,logs,e

    @patch('y5_queue_guard.analyze',return_value=dict(quality=dict(status='FAIL'),shared_resources=[],samples=[]))
    def test_rejected_capture_and_business_continues(self,unused):
        r,raw,logs,e=self.data(); self.assertEqual(check(r,raw,logs,e)['status'],'PASS_PROTECTION_ONLY')
        self.assertEqual(check(None,None,*self.data(False)[2:])['status'],'PASS_PROTECTION_ONLY')

    @patch('y5_queue_guard.analyze',return_value=dict(quality=dict(status='FAIL'),shared_resources=[],samples=[]))
    def test_output_only_disable_and_false_rate_rejected(self,unused):
        r,raw,logs,e=self.data(); e['after']['native']=native(30001)
        self.assertIn('source_still_active_after_detach',check(r,raw,logs,e)['errors'])
        r,raw,logs,e=self.data(); raw=raw.replace(b'30000',b'10000')
        self.assertIn('entry_guard_proof',check(r,raw,logs,e)['errors'])

    def test_rejected_capture_cannot_publish_relations(self):
        with patch('y5_queue_guard.analyze',return_value=dict(quality=dict(status='PASS'),shared_resources=[{}],samples=[])):
            self.assertIn('rejected_capture_promoted',check(*self.data())['errors'])

    def test_native_cpu_duplicates_and_decrease(self):
        self.assertEqual(native_totals(native(16))['entries'],16)
        with self.assertRaises(ValueError): native_totals(native(16)+native(16).splitlines()[1])
        with self.assertRaises(ValueError): source_delta(native(16),native(0))
