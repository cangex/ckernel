# SPDX-License-Identifier: GPL-2.0
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'container_interference'))
from fd_relation_population import RELATION_PLAN, check_relations


class FDRelationPopulation(unittest.TestCase):
    def fixture(self):
        calls=[]; logs=[]; edges=[]
        for container in range(2):
            local=[]
            for op in range(16):
                t=1000+op*1000
                for thread in range(2):
                    q=dict(object=10+container,files=20+container,cgroup_id=30+container,
                           tgid=40+container,tid=50+2*container+thread,
                           begin_ns=t+thread*50,acquired_ns=t+10+thread*200,
                           release_begin_ns=t+200+thread*200,released_ns=t+220+thread*200)
                    local.append(q)
                h,w=local[-2:]
                edges.append(dict(resource='files_struct_lock',object=hex(h['object']),
                                  holder=[h['cgroup_id'],1,(h['tgid']<<32)|h['tid'],1],
                                  waiter=[w['cgroup_id'],1,(w['tgid']<<32)|w['tid'],2],
                                  wait_begin_ns=t+60,wait_end_ns=t+205,begin_ns=t+60,end_ns=t+190))
            calls+=local
            logs.append('\n'.join('CIS_FD_TRUTH '+json.dumps(q) for q in local)+'\nCIS_FD_DONE '+
                        json.dumps(dict(threads=2,operations_per_thread=16,native=0,failed=0)))
        return logs,dict(start_ns=1,end_ns=18000),dict(quality=dict(status='PASS'),findings=edges)

    def run_case(self,report=None,plan=RELATION_PLAN):
        logs,window,original=self.fixture()
        return check_relations(logs,b'',window,'threads',report if report is not None else original,plan)

    def test_independent_relation_denominator_and_scope(self):
        r=self.run_case()
        self.assertEqual((r['status'],r['eligible'],r['captured'],r['capture_ratio']),('PASS_SCOPED',32,32,1))
        self.assertIsNone(r['true_blocking_recall'])
        self.assertEqual(r['design'],'PREDECLARED')

    def test_empty_and_partial_output_do_not_trim_truth(self):
        _,_,r=self.fixture();r['findings']=r['findings'][:16]
        out=self.run_case(r)
        self.assertEqual((out['eligible'],out['captured'],out['capture_ratio']),(32,16,.5))
        self.assertEqual(out['status'],'FAIL')
        old=self.run_case(r,plan=None)
        self.assertEqual((old['status'],old['threshold_status']),('PASS_SCOPED','FAIL'))
        r['findings']=[]
        self.assertEqual(self.run_case(r)['eligible'],32)

    def test_duplicates_and_false_holder_do_not_inflate_ratio(self):
        _,_,r=self.fixture();r['findings']+=[r['findings'][0]]
        self.assertIn('duplicate_relation_for_truth_pair',self.run_case(r)['errors'])
        _,_,r=self.fixture();r['findings'][-1]['holder'][0]=999
        self.assertIn('relation_not_in_independent_population',self.run_case(r)['errors'])

    def test_private_object_and_other_lifetime_cannot_fill_missing_pair(self):
        for mutation in (dict(object='0x123'),dict(begin_ns=17000,end_ns=17001),dict(wait_end_ns=17000)):
            _,_,r=self.fixture();r['findings'][-1].update(mutation)
            self.assertIn('relation_not_in_independent_population',self.run_case(r)['errors'])

    def test_incomplete_display_cannot_claim_complete_audit(self):
        _,_,r=self.fixture();r['omitted_findings']=1
        self.assertIn('incomplete_relation_audit',self.run_case(r)['errors'])

    def test_posthoc_selection_and_lower_gate_rejected(self):
        for key,value in (('selection','observed edges'),('minimum_capture_ratio',.5)):
            p=copy.deepcopy(RELATION_PLAN);p[key]=value
            with self.assertRaisesRegex(ValueError,'plan changed'): self.run_case(plan=p)


if __name__=='__main__': unittest.main()
