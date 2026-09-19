# SPDX-License-Identifier: GPL-2.0
import copy
import unittest
from unittest.mock import patch

from mixed_vm_check import PLAN,order,roles,selected,overlap,verify_state,comparisons
from net_fixture_check import check_case
import test_net_fixture_check as net_test


class MixedTruth(unittest.TestCase):
    def sample(self,case='shared',r=0):
        _,network,_,_=net_test.NetFixture().fixture(case)
        block=[]
        for actor in range(2):
            lines=['CIS_SESSION_CONTAINER host_pid=%d'%(200+actor),
                   'CIS_BLOCK_BEGIN role=%d major=8 minor=%d start_ns=20'%(actor,actor if case=='private' else 0)]
            for i in range(4):
                for op in ('write','read'):
                    lines.append('CIS_BLOCK_IO role=%d iteration=%d op=%s offset=%d before_ns=%d after_ns=%d bytes=4096 verified=1'%
                        (actor,i,op,(1+actor*8+i)*4096,20+100*i,21+100*i))
            block.append('\n'.join(lines+['CIS_BLOCK_DONE operations=8 errors=0']))
        ordinary=[]
        for mode in PLAN['ordinary_workloads']:
            ordinary.append('CIS_JOINT_WORK mode=%s due_start_ns=1 begin_ns=2 end_ns=3000000001 offered=1500 completed=1500 errors=0 timeouts=0 period_ns=2000000 timeout_ns=100000000 p99_ns=1485 max_ns=1500 latency_sum_ns=1125750\n'%mode+
                'CIS_JOINT_LATENCIES '+','.join(map(str,range(1,1501)))+'\n')
        registered=['a','b','c','d']; net_roots,block_roots=roles(r)
        ev=dict(label='%s-off%d'%(case,r),case=case,round=r,mode='off',session_id=None,
            registered=registered,targets=[registered[i] for i in selected(r,'off')],
            network_roots=net_roots,block_roots=block_roots,ordinary_exit_codes=[0]*4,fixture_exit_codes=[0]*4,
            start_ns=1,window=dict(start_ns=2,end_ns=1000),before=dict(read_end_ns=0,time_ns=0,net_source_audit=''),
            after=dict(time_ns=4_000_000_000,net_source_audit=''),active_sources={},idle_sources={})
        return ev,ordinary,network,block

    def test_fixed_matrix_covers_each_container_in_each_role(self):
        self.assertEqual(len(order()),24)
        self.assertEqual(sum(mode!='off' for _,_,mode in order()),18)
        self.assertEqual(len({tuple(row) for row in order()}),24)
        for r in range(3):
            network,block=roles(r)
            self.assertEqual(sorted(network+block),list(range(4)))
            self.assertEqual(selected(r,'net'),network)
            self.assertEqual(selected(r,'block'),block)
        self.assertEqual(set(i for r in range(3) for i in roles(r)[0]),set(range(4)))
        self.assertEqual(set(i for r in range(3) for i in roles(r)[1]),set(range(4)))

    @patch('mixed_vm_check.costs',return_value={})
    @patch('mixed_vm_check.net_delta',return_value=dict(totals=dict(entries=0)))
    @patch('mixed_vm_check.validate')
    def test_off_checks_both_independent_sources_not_presence_only(self,*mocks):
        for case in ('shared','private'):
            ev,ordinary,net,block=self.sample(case)
            result=verify_state(ev,ordinary,net,block,None,None,100)
            self.assertEqual(result['overlapping_operations'],16)
            self.assertEqual(result['network']['eligible'],4 if case=='shared' else 0)
            self.assertEqual(result['block']['successful_operations'],16)
            self.assertEqual(result['block']['unique_blocking_container'],'NOT_ESTABLISHED')

    def test_all_sixteen_io_operations_must_overlap_native_holder(self):
        ev,_,net,block=self.sample()
        truth=check_case('shared',ev['window'],net)['truth']
        self.assertEqual(overlap(truth,block),16)
        block[0]=block[0].replace('before_ns=20 after_ns=21','before_ns=80 after_ns=81',1)
        with self.assertRaisesRegex(ValueError,'did not overlap'): overlap(truth,block)

    @patch('mixed_vm_check.costs',return_value={})
    @patch('mixed_vm_check.net_delta',return_value=dict(totals=dict(entries=0)))
    @patch('mixed_vm_check.validate')
    def test_role_window_failure_and_missing_population_are_rejected(self,*mocks):
        for fault in ('roles','exit','coverage','cost','missing','io','timeout'):
            ev,ordinary,net,block=self.sample()
            if fault=='roles': ev['network_roots']=[2,3]
            elif fault=='exit': ev['fixture_exit_codes'][0]=1
            elif fault=='coverage': ev['window']['end_ns']=4_000_000_000
            elif fault=='cost': ev['before']['read_end_ns']=1
            elif fault=='missing': ordinary.pop()
            elif fault=='io': block[0]=block[0].replace('verified=1','verified=0',1)
            else: ordinary[0]=ordinary[0].replace('timeouts=0','timeouts=1')
            with self.subTest(fault=fault),self.assertRaises(ValueError):
                verify_state(ev,ordinary,net,block,None,None,100)

    @patch('mixed_vm_check.costs',return_value={})
    @patch('mixed_vm_check.net_delta',return_value=dict(totals=dict(entries=1)))
    @patch('mixed_vm_check.validate')
    def test_off_rejects_inactive_network_callback_activity(self,*mocks):
        args=self.sample()
        with self.assertRaisesRegex(ValueError,'active outside NET'): verify_state(*args,None,None,100)

    @patch('mixed_vm_check.costs',return_value={})
    @patch('mixed_vm_check.net_delta',return_value=dict(totals=dict(entries=0)))
    @patch('mixed_vm_check.validate')
    def test_network_relation_cannot_borrow_unrelated_io_actor(self,*mocks):
        ev,ordinary,net,block=self.sample(); ev.update(mode='net',label='shared-net0',session_id='1',targets=['a','b'])
        _,_,report,identities=net_test.NetFixture().fixture()
        record=dict(session_id='1',collector='net',nonce='sharednet0',targets=ev['targets'],objects_absent=True,window=ev['window'],
            requested_ns=1,receipt=dict(prepared_ns=1,destroyed_ns=1001),root_identities=dict(zip(ev['targets'],identities)))
        report['sockets'][0]['waits'][0]['observed_holders'][0]['holder'][0]=3
        with patch('mixed_vm_check.analyze',return_value=dict(quality=dict(status='PASS'),scope_audit=dict(status='PASS'))), \
             patch('mixed_vm_check.net_report',return_value=report),self.assertRaisesRegex(ValueError,'independent truth'):
            verify_state(ev,ordinary,net,block,record,b'raw',100)

    def test_off_comparison_stays_in_same_case_and_round(self):
        off=dict(case='shared',round=0,mode='off',workload=[dict(p99_ns=10,throughput_per_second=500,timeouts=0)]*4)
        on=copy.deepcopy(off);on['mode']='net'
        self.assertEqual([r['role'] for r in comparisons([off,on])],['target','target','bystander','bystander'])
        off['case']='private'
        with self.assertRaises(ValueError): comparisons([off,on])


if __name__=='__main__': unittest.main()
