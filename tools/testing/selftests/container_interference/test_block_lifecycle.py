# SPDX-License-Identifier: GPL-2.0
import copy
from pathlib import Path
import unittest
from block_lifecycle_check import CASES, INFLIGHT_CASES, case_order, check_case, check_counters


class LifecycleTruth(unittest.TestCase):
    window = dict(start_ns=1, end_ns=100)
    identities = [dict(id=1, generation=1), dict(id=2, generation=1)]

    def inputs(self, case):
        s={**CASES,**INFLIGHT_CASES}[case]
        count=0 if s==2 else 1 if s==0 or s>=4 else 2; logs=[]; rows=[]
        for role in range(2):
            pid=101+role; parent=2000+role*10; size=4096 if s==0 or s>=4 else 8192
            lines=[f'CIS_SESSION_CONTAINER host_pid={pid}',
                f'CIS_LIFECYCLE_JOB role={role} scenario={s} begin_ns=10 end_ns=90 rc=0 original_bio={parent} bytes={size} requests={count} completed={int(s!=2)} io_errors={int(s in (3,4))} canceled={int(s in (2,4))} verified=1']
            if s>=4:
                lines.append('CIS_LIFECYCLE_INFLIGHT submit_return_ns=22 finish_begin_ns=24 finish_end_ns=28 pending_seen=1 started_seen=1')
            for i in range(count):
                # Sequential request address reuse is valid; episode boundaries distinguish it.
                address=1000+role; bio=parent+i; begin=20+i*20; end=25+i*20; status=10 if s in (3,4) else 0
                lines.append(f'CIS_LIFECYCLE_RQ request={address} bio={bio} begin_ns={begin} end_ns={end} sector={(1+role*32)*8+i*8} bytes=4096 status={status}')
                rows.append(dict(request=address,episode_ns=begin-1,submitter=[role+1,1,(pid<<32)|pid,3],
                    episode_interval_ns=[begin-1,end+1],terminal='data_completion',initial_bio=bio,initial_bytes=4096,
                    operation=1,queue_intervals_ns=[],completions=[dict(bytes=4096,status=status)],
                    service_intervals=[dict(interval_ns=[begin+1,end+1])],uncertainty={},blocking_container=None,
                    head_bio_origins=[dict(registered_container=[role+1,1],ancestor_overdepth=False,bytes=4096)]))
            logs.append('\n'.join(lines))
        return logs,dict(quality=dict(status='PASS'),scope_audit=dict(status='PASS'),requests=rows)

    def test_real_scenarios_and_counter_conservation(self):
        self.assertEqual(len(case_order()),24)
        self.assertEqual(case_order()[8:10],['plain-block-r2','plain-off-r2'])
        for case in CASES:
            logs,report=self.inputs(case)
            r=check_case(case,self.window,logs,report,self.identities)
            self.assertEqual(r['status'],'PASS',r)
            before=dict(requests=0,completions=0,requeues=0,partials=0,errors=0)
            after=dict(before,requests=r['driver_requests'],completions=r['driver_requests'],
                       errors=r['driver_requests'] if case=='error' else 0)
            self.assertEqual(check_counters(case,before,after,r)['status'],'PASS')
            after['requests']+=1
            self.assertEqual(check_counters(case,before,after,r)['status'],'FAIL')

    def test_missing_or_wrong_request_is_not_split_success(self):
        logs,original=self.inputs('split')
        for field,value in [('initial_bytes',8192),('initial_bio',0),('submitter',[2,1,1,1]),
                            ('blocking_container',[2,1]),('terminal','UNOBSERVED'),('uncertainty',{'lost':1})]:
            report=copy.deepcopy(original); report['requests'][0][field]=value
            self.assertEqual(check_case('split',self.window,logs,report,self.identities)['status'],'FAIL')
        report=copy.deepcopy(original); report['requests'].pop()
        self.assertEqual(check_case('split',self.window,logs,report,self.identities)['status'],'FAIL')

    def test_cancel_has_no_request_and_error_is_not_success(self):
        logs,report=self.inputs('cancel'); report['requests']=self.inputs('plain')[1]['requests']
        self.assertEqual(check_case('cancel',self.window,logs,report,self.identities)['status'],'FAIL')
        logs,report=self.inputs('error'); report['requests'][0]['completions'][0]['status']=0
        self.assertEqual(check_case('error',self.window,logs,report,self.identities)['status'],'FAIL')

    def test_truth_corruption_rejected(self):
        for old,new in [('sector=8','sector=16'),('bytes=8192','bytes=4096'),('original_bio=2000','original_bio=999'),
                        ('completed=1','completed=2'),('verified=1','verified=0'),('end_ns=25','end_ns=101')]:
            logs,_=self.inputs('split'); logs[0]=logs[0].replace(old,new)
            self.assertEqual(check_case('split',self.window,logs)['status'],'FAIL')

    def test_fixture_calls_native_split_and_original_endio(self):
        src=(Path(__file__).parent/'block_fixture/cis_block_fixture.c').read_text()
        for token in ('submit_bio(bio);','wait_for_completion(&job->done);','blk_mq_end_request(rq, result);',
                      'bio->bi_end_io = cis_lifecycle_done','QUEUE_FLAG_NOMERGES'):
            self.assertIn(token,src)
        self.assertNotIn('trace_block',src)
        self.assertNotIn('bio_split(',src)

    def test_inflight_abort_and_drain_frozen_plan(self):
        self.assertEqual(len(case_order(True)),12)
        self.assertEqual(case_order(True)[4:6],['abort-block-r2','abort-off-r2'])
        for case in INFLIGHT_CASES:
            logs,report=self.inputs(case)
            r=check_case(case,self.window,logs,report,self.identities)
            self.assertEqual(r['status'],'PASS',r)
            self.assertEqual(r['driver_aborted_inflight'],case=='abort')
            self.assertFalse(r['canceled_before_submit'])
            before=dict(requests=0,completions=0,requeues=0,partials=0,errors=0)
            after=dict(before,requests=2,completions=2,errors=2 if case=='abort' else 0)
            self.assertEqual(check_counters(case,before,after,r)['status'],'PASS')

    def test_inflight_requires_started_pending_request_and_terminal_bracket(self):
        for old,new in [('pending_seen=1','pending_seen=0'),('started_seen=1','started_seen=0'),
                        ('submit_return_ns=22','submit_return_ns=29'),('finish_end_ns=28','finish_end_ns=24'),
                        ('io_errors=1','io_errors=0'),('canceled=1','canceled=0')]:
            logs,report=self.inputs('abort'); logs[0]=logs[0].replace(old,new)
            self.assertEqual(check_case('abort',self.window,logs,report,self.identities)['status'],'FAIL')
        logs,report=self.inputs('abort')
        report['requests'][0]['episode_interval_ns'][1]=30
        self.assertEqual(check_case('abort',self.window,logs,report,self.identities)['status'],'FAIL')

    def test_inflight_is_not_presubmit_cancel_or_blocker_proof(self):
        logs,report=self.inputs('cancel')
        self.assertEqual(check_case('abort',self.window,logs,report,self.identities)['status'],'FAIL')
        logs,report=self.inputs('abort'); report['requests'][0]['blocking_container']=[2,1]
        self.assertEqual(check_case('abort',self.window,logs,report,self.identities)['status'],'FAIL')

    def test_inflight_fixture_retains_request_until_driver_terminal(self):
        src=(Path(__file__).parent/'block_fixture/cis_block_fixture.c').read_text()
        for token in ('job->pending = rq;', 'complete(&job->dispatched);',
                      'wait_for_completion(&job->dispatched);', 'blk_mq_request_started(rq)',
                      '!completion_done(&job->done)', 'blk_mq_end_request(rq, status);'):
            self.assertIn(token,src)
