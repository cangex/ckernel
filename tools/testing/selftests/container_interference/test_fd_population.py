# SPDX-License-Identifier: GPL-2.0
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'container_interference'))
from fd_population_check import POPULATION_PLAN, check_population


class FDPopulation(unittest.TestCase):
    def fixture(self):
        logs, events = [], []
        for container in range(2):
            truth = []
            for op in range(16):
                t = 1000 + op * 1000
                q = dict(object=10+container, files=20+container, cgroup_id=30+container,
                         tgid=40+container, tid=40+container, begin_ns=t,
                         acquired_ns=t+100, release_begin_ns=t+200, released_ns=t+300)
                truth.append(q)
                for phase, time in ((2,t+10), (3,t+90), (4,t+210)):
                    e = dict(resource=3, object=q['object'], actor_id=q['cgroup_id'],
                             actor_tid=(q['tgid']<<32)|q['tid'], actor_start=10,
                             actor_generation=1, epoch=100, protocol=2,
                             sample_time_ns=time, phase=phase, attempt_ns=t+10)
                    events.append(dict(kind='OWNER', session_id=1,
                                       detail=' '.join('%s=%s'%item for item in e.items())))
            logs.append('\n'.join('CIS_FD_TRUTH '+json.dumps(q) for q in truth)+
                        '\nCIS_FD_DONE '+json.dumps(dict(threads=1, operations_per_thread=16, native=0, failed=0)))
        return logs, events, dict(start_ns=1,end_ns=20000)

    def run_check(self, events=None, plan=POPULATION_PLAN):
        logs, original, window = self.fixture()
        return check_population(logs, '\n'.join(map(json.dumps,original if events is None else events)),
                                window, 'private',plan)

    def test_complete_calls_have_independent_denominator(self):
        r=self.run_check()
        self.assertEqual(r['status'],'PASS_SCOPED')
        self.assertEqual((r['truth_calls'],r['complete_calls'],r['complete_call_coverage']),(32,32,1))
        self.assertIsNone(r['relationship_recall'])
        self.assertEqual(r['design'],'PREDECLARED')

    def test_absent_records_do_not_erase_eligibility(self):
        r=self.run_check([])
        self.assertEqual((r['truth_calls'],r['unobserved_calls'],r['complete_call_coverage']),(32,32,0))
        self.assertEqual(r['status'],'PASS_SCOPED')  # Accounting passed, recall did not.

    def test_prefix_and_partial_do_not_shrink_population(self):
        _,events,_=self.fixture()
        prefix=dict(kind='OWNER',session_id=1,detail='resource=3 object=10 phase=11 epoch=100 sample_time_ns=3010')
        r=self.run_check(events[:7]+[prefix])
        self.assertEqual((r['truth_calls'],r['complete_calls'],r['partial_calls'],r['unobserved_calls']),(32,2,1,29))
        self.assertEqual(r['prefix_markers'],1)
        self.assertEqual(r['complete_call_coverage'],2/32)

    def test_duplicate_event_cannot_raise_recall(self):
        _,events,_=self.fixture()
        r=self.run_check(events+[events[0]])
        self.assertIn('duplicate_observation_for_truth_call',r['errors'])
        self.assertLess(r['complete_calls'],r['truth_calls'])

    def test_identity_and_attempt_changes_reject_pairs(self):
        for old,new in (('actor_start=10','actor_start=11'),('attempt_ns=1010','attempt_ns=1011'),
                        ('epoch=100','epoch=101'),('protocol=2','protocol=1')):
            _,events,_=self.fixture(); events[1]['detail']=events[1]['detail'].replace(old,new)
            r=self.run_check(events)
            self.assertEqual(r['status'],'FAIL')
            self.assertEqual(r['complete_calls'],31)

    def test_private_object_or_other_actor_cannot_fill_missing_record(self):
        _,events,_=self.fixture();events[0]['detail']=events[0]['detail'].replace('object=10','object=11')
        r=self.run_check(events)
        self.assertEqual(r['complete_calls'],31)
        self.assertIsNone(r['relationship_recall'])

    def test_truth_duplicates_or_window_clipping_reject(self):
        logs,events,window=self.fixture();logs[0]=logs[0].replace('"begin_ns": 2000','"begin_ns": 1000')
        r=check_population(logs,'\n'.join(map(json.dumps,events)),window,'private',POPULATION_PLAN)
        self.assertIn('duplicate_or_overlapping_truth_call',r['errors'])
        logs,events,window=self.fixture();window['end_ns']=15000
        r=check_population(logs,'\n'.join(map(json.dumps,events)),window,'private',POPULATION_PLAN)
        self.assertIn('truth_outside_window_or_order',r['errors'])
        self.assertEqual(r['truth_calls'],32)

    def test_plan_cannot_be_changed_to_observed_selection(self):
        plan=copy.deepcopy(POPULATION_PLAN);plan['selection']='observed calls only'
        with self.assertRaisesRegex(ValueError,'plan changed'): self.run_check(plan=plan)
        self.assertEqual(self.run_check(plan=None)['design'],'RETROSPECTIVE_REPLAY')

    def test_no_fake_native_denominator(self):
        logs=['CIS_FD_DONE '+json.dumps(dict(threads=2,operations_per_thread=16,native=1,failed=0))]*2
        r=check_population(logs,'',dict(start_ns=1,end_ns=2000),'native',POPULATION_PLAN)
        self.assertEqual(r['status'],'PASS_SCOPED')
        self.assertIsNone(r['complete_call_coverage'])
        self.assertEqual(r['denominator_status'],'UNAVAILABLE_NATIVE')

    def test_mixed_sessions_rejected(self):
        _,events,_=self.fixture();events[0]['session_id']=2
        self.assertIn('mixed_sessions',self.run_check(events)['errors'])

    def test_total_calls_cannot_hide_inconsistent_task_population(self):
        logs,events,window=self.fixture()
        logs[0]=logs[0].replace('"tid": 40','"tid": 99',1)
        r=check_population(logs,'\n'.join(map(json.dumps,events)),window,'private',POPULATION_PLAN)
        self.assertIn('truth_task_population',r['errors'])
        logs,events,window=self.fixture()
        logs[0]=logs[0].replace('"tid": 40','"tid": 4294967296')
        r=check_population(logs,'',window,'private',POPULATION_PLAN)
        self.assertIn('truth_task_id_range',r['errors'])


if __name__=='__main__': unittest.main()
