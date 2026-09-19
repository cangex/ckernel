# SPDX-License-Identifier: GPL-2.0
import json
import unittest
from unittest.mock import patch
from net_guard_check import check
from source_switches import expected_fields
import test_net_report


class NetGuard(unittest.TestCase):
    def fixture(self):
        record=test_net_report.NetReport().record()
        record.update(result='PARTIAL',state='IDLE',finalized=True,objects_absent=True,requested_ns=0)
        record['receipt'].update(result='PARTIAL',reason='ENTRY_RATE_LIMIT')
        rows=[dict(kind='entry_budget_disable',detail='configured_limit=200000 delta_entries=300000 interval_ns=1000000000'),
              dict(kind='terminal_counters',detail='received=300000 emitted=20000 rejected=0'),
              dict(kind='terminal_coverage',detail='lost=0 owner_skipped=0')]
        for row in rows: row['session_id']='7'
        raw='\n'.join(json.dumps(r) for r in rows).encode()
        logs=['\n'.join('CIS_NET_STORM '+json.dumps(dict(actor=a,bucket=i,cookie=a+1,
            begin_ns=300+i*500,end_ns=800+i*500,operations=100,errors=0)) for i in range(8)) for a in range(2)]
        def snap(t,n):
            return dict(time_ns=t,source_audit='version=1 active=0 release_active=0 shift=0 source_counter_bytes_per_cpu=40 snapshot=non_atomic\n'
                'cpu=0 entries=%d eligible=%d selected=%d releases=0 skipped=0\n'%(n,n,n))
        ev=dict(source_before=snap(0,0),source_detached=snap(200,2000),source_after=snap(5000,2000),
            active_sources=dict(before_ns=10,after_ns=11,expected_collector='net',observed=expected_fields('5','net')),
            idle_sources=dict(before_ns=150,after_ns=151,expected_collector=None,observed=expected_fields('5',None)))
        return [record,raw,logs,ev]

    def test_protection_pass_never_accepts_dense_attribution(self):
        args=self.fixture(); r=check(*args)
        self.assertEqual(r['status'],'PASS',r)
        args[0]['result']='COMPLETE'
        self.assertIn('capture_or_cleanup',check(*args)['errors'])
        with patch('net_guard_check.analyze',return_value=dict(quality=dict(status='FAIL'),sockets=[{}],tx=dict(episodes=[]))):
            self.assertIn('incomplete_capture_admitted_relations',check(*args)['errors'])

    def test_rate_cpu_loss_and_data_need_actual_proof(self):
        args=self.fixture(); args[1]=args[1].replace(b'200000',b'900000')
        self.assertIn('entry_stop_without_rate_proof',check(*args)['errors'])
        for reason,error in (('WORKER_CPU_LIMIT','cpu_stop_without_cost'),('QUALITY','quality_stop_without_ring_loss'),
                             ('DATA_LIMIT','data_stop_without_output'),('COMPLETE','unexpected_stop_reason')):
            args=self.fixture(); args[0]['receipt']['reason']=reason
            self.assertIn(error,check(*args)['errors'])
        args=self.fixture(); args[0]['receipt'].update(reason='WORKER_CPU_LIMIT',armed_capture_cpu_ns=21000000)
        self.assertEqual(check(*args)['status'],'PASS')

    def test_no_business_stopping_or_sources_left_on(self):
        args=self.fixture(); args[2][0]=args[2][0].replace('"operations": 100','"operations": 0')
        self.assertIn('business_progress',check(*args)['errors'])
        args=self.fixture(); args[3]['idle_sources'].update(before_ns=5000,after_ns=5001)
        self.assertIn('no_business_after_detach',check(*args)['errors'])
        args=self.fixture(); args[3]['source_after']['source_audit']=args[3]['source_after']['source_audit'].replace('2000','2001')
        self.assertIn('callbacks_after_detach',check(*args)['errors'])
        args=self.fixture(); args[3]['idle_sources']['observed']['net']='1'
        with self.assertRaises(ValueError): check(*args)

    def test_private_object_identity_must_not_be_shared(self):
        args=self.fixture(); args[2][1]=args[2][1].replace('"cookie": 2','"cookie": 1')
        self.assertIn('private_socket_identity',check(*args)['errors'])


if __name__=='__main__': unittest.main()
