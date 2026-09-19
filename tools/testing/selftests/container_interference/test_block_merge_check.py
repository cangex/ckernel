# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import unittest
from block_merge_check import CASES, SCHEDULER_CASES, case_order, check_case, check_counters


class MergeTruth(unittest.TestCase):
    def logs(self,case):
        count,pattern={**CASES,**SCHEDULER_CASES}[case]; nr=count if case=='gap' else 1; out=[]
        for role in range(2):
            lines=[f'CIS_SESSION_CONTAINER host_pid={101+role}',
                f'CIS_MERGE_JOB role={role} count={count} pattern={pattern} begin_ns=10 end_ns=90 rc=0 requests={nr} completed={count} errors=0 verified=1']
            for i in range(nr):
                n=1 if case=='gap' else count
                lines.append(f'CIS_MERGE_RQ request={1000+role*100+i} begin_ns={20+i*10} end_ns={25+i*10} bytes={4096*n} bios={n}')
            out.append('\n'.join(lines))
        return out

    def test_truth_cases_and_alternation(self):
        self.assertEqual(len(case_order()),24)
        self.assertEqual(case_order()[:2],['back-off-r1','back-block-r1'])
        self.assertEqual(case_order()[8:10],['back-block-r2','back-off-r2'])
        for case in {**CASES,**SCHEDULER_CASES}:
            result=check_case(case,dict(start_ns=1,end_ns=100),self.logs(case))
            self.assertEqual(result['status'],'PASS',result)
            before=dict(requests=1,completions=1,requeues=0,partials=0,errors=0)
            after=dict(before,requests=1+result['driver_requests'],completions=1+result['driver_requests'])
            self.assertEqual(check_counters(before,after,result)['status'],'PASS')
            after['errors']=1; self.assertEqual(check_counters(before,after,result)['status'],'FAIL')

    def test_wrong_or_missing_truth_rejected(self):
        for old,new in (('verified=1','verified=0'),('bytes=8192','bytes=4096'),('bios=2','bios=1'),
                        ('requests=1','requests=0'),('end_ns=25','end_ns=101')):
            logs=self.logs('back'); logs[0]=logs[0].replace(old,new)
            self.assertEqual(check_case('back',dict(start_ns=1,end_ns=100),logs)['status'],'FAIL')

    def test_zero_coverage_cannot_pass(self):
        report=dict(quality=dict(status='PASS'),scope_audit=dict(status='PASS'),requests=[],provenance={})
        r=check_case('back',dict(start_ns=1,end_ns=100),self.logs('back'),report,
                     [dict(id=1,generation=1),dict(id=2,generation=1)])
        self.assertEqual(r['status'],'FAIL')

    def test_fixture_calls_real_native_apis(self):
        root=Path(__file__).parent
        src=(root/'block_fixture/cis_block_fixture.c').read_text()
        for call in ('blk_start_plug(&plug)','submit_bio(bios[i])','blk_finish_plug(&plug)',
                     'blk_mq_start_request(rq)','blk_mq_end_request(rq, result)'):
            self.assertIn(call,src)
        self.assertNotIn('trace_block',src)
        self.assertIn('if (test_mode < 3 || test_mode == 5) blk_queue_flag_set(QUEUE_FLAG_NOMERGES',src)
