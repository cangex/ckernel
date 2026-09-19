# SPDX-License-Identifier: GPL-2.0
import copy
from pathlib import Path
import unittest
from unittest.mock import patch

from rwsem_joint import PLAN, roles, verify, verify_fixture_schedule, comparisons
from coverage_matrix import VERIFIERS


class RwsemJoint(unittest.TestCase):
    def sample(self, round_number=0):
        mapping=roles(round_number)
        jobs=[dict(log='reset0',actor_index=mapping[0],token=1,arguments=dict(reset=True,slot=0)),
              dict(log='reset1',actor_index=mapping[0],token=1,arguments=dict(reset=True,slot=1)),
              dict(log='holder',actor_index=mapping[0],token=1,arguments=dict(mode=1,hold=200)),
              dict(log='waiter',actor_index=mapping[1],token=1,arguments=dict(mode=0,wait_holders=1))]
        info=dict(logs=['a','b','c','d'],exit_codes=[0]*4,start_ns=1000,
                  before=dict(time_ns=1,read_end_ns=500,rwsem_source_audit='version=1\ncpu=0 entries=0 filtered=0\n'),
                  after=dict(time_ns=4_000_000_000,rwsem_source_audit='version=1\ncpu=0 entries=1000 filtered=990\n'))
        state=dict(round=round_number,case='writeRead',enabled=True,registered=['A','B','C','D'],
                   targets=[['A','B','C','D'][i] for i in mapping[:2]],
                   jobs=jobs,logs=[j['log'] for j in jobs],joint=info)
        logs={}
        for name,mode in zip(info['logs'],PLAN['ordinary_workloads']):
            logs[name]=('CIS_JOINT_WORK mode=%s due_start_ns=1000 begin_ns=1100 end_ns=3000001000 offered=1500 completed=1500 errors=0 timeouts=0 period_ns=2000000 timeout_ns=100000000 p99_ns=1485 max_ns=1500 latency_sum_ns=1125750\n'%mode+
                        'CIS_JOINT_LATENCIES '+','.join(map(str,range(1,1501)))+'\n')
        return state,logs,dict(window=dict(start_ns=1_000_000,end_ns=2_001_000_000),
            requested_ns=900_000,receipt=dict(prepared_ns=950_000,destroyed_ns=2_100_000_000,
                                           terminal=dict(valid=True,received=10)))

    @patch('rwsem_joint.cost_analysis',return_value=dict(scope='bookends'))
    def test_four_active_containers_and_rotation_are_verified(self,mock):
        for round_number in range(3):
            state,logs,record=self.sample(round_number)
            r=verify(PLAN,state,logs,record,100)
            self.assertEqual(len(r['workload']),4)
            self.assertFalse(r['observer_kernel_cpu_complete'])
            self.assertEqual(r['native_source']['selected'],10)
            self.assertEqual(roles(round_number)[:2],PLAN['targets_by_round'][round_number])
        self.assertEqual(mock.call_count,3)

    @patch('rwsem_joint.cost_analysis',return_value={})
    def test_source_counters_required_and_off_must_be_inactive(self,mock):
        state,logs,record=self.sample(); state['enabled']=False
        with self.assertRaisesRegex(ValueError,'active in OFF'): verify(PLAN,state,logs,None,100)
        state,logs,record=self.sample()
        state['joint']['after']['rwsem_source_audit']='version=1\ncpu=0 entries=10 filtered=0\n'
        with self.assertRaisesRegex(ValueError,'not exercised'): verify(PLAN,state,logs,record,100)

    @patch('rwsem_joint.cost_analysis',return_value={})
    def test_native_and_bpf_audits_have_matching_boundaries(self,mock):
        state,logs,record=self.sample(); record['receipt']['terminal']['received']=11
        with self.assertRaisesRegex(ValueError,'exceed audited'): verify(PLAN,state,logs,record,100)
        state,logs,record=self.sample(); record['requested_ns']=400
        with self.assertRaisesRegex(ValueError,'producer lifetime'): verify(PLAN,state,logs,record,100)

    @patch('rwsem_joint.cost_analysis',return_value={})
    def test_missing_bystander_or_incomplete_window_rejected(self,mock):
        state,logs,record=self.sample(); state['joint']['exit_codes']=[0,0,0,1]
        with self.assertRaisesRegex(ValueError,'four complete'): verify(PLAN,state,logs,record,100)
        state,logs,record=self.sample();record['window']['end_ns']=4_000_000_000
        with self.assertRaisesRegex(ValueError,'full diagnostic'): verify(PLAN,state,logs,record,100)
        state,logs,record=self.sample(); state['targets']=['A','C']
        with self.assertRaisesRegex(ValueError,'target rotation'): verify(PLAN,state,logs,record,100)

    def test_fixed_fixture_job_population_cannot_be_reduced_or_relabelled(self):
        for mutation in ('missing','holder','token','mode','log'):
            state,_,_=self.sample()
            if mutation=='missing': state['jobs'].pop()
            elif mutation=='holder': state['jobs'][2]['actor_index']=3
            elif mutation=='token': state['jobs'][3]['token']=2
            elif mutation=='mode': state['jobs'][2]['arguments']['mode']=0
            else: state['logs'][-1]=state['logs'][0]
            with self.assertRaises(ValueError): verify_fixture_schedule(state)

    def test_comparison_is_same_case_same_round_not_quiet_baseline(self):
        s=dict(round=1,case='private',enabled=True,joint=dict(workload=[dict(throughput_per_second=500,p99_ns=12,timeouts=0)]*4))
        off=copy.deepcopy(s);off['enabled']=False
        r=comparisons([off,s])
        self.assertEqual([v['role'] for v in r],['bystander','bystander','target','target'])
        off['case']='writeRead'
        with self.assertRaisesRegex(ValueError,'same-case'): comparisons([off,s])

    def test_joint_coverage_requires_joint_producer_not_historical_rwsem(self):
        self.assertEqual(VERIFIERS['rwsem_joint'],('rwsem_vm_check','rwsem_joint',dict(joint=True)))
        source=(Path(__file__).parent/'rwsem_vm.py').read_text()
        self.assertIn('verify_joint(plan',source)
        self.assertIn("children[fixture_begin:]",source)
        self.assertIn("record,plan['clock_ticks']",source)


if __name__=='__main__': unittest.main()
