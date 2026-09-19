# SPDX-License-Identifier: GPL-2.0
import unittest
from block_fixture_check import case_order,check_case,check_counters,COUNTERS


class BlockFixture(unittest.TestCase):
    def logs(self,private=False):
        result=[]
        for role in range(2):
            rows=['CIS_SESSION_CONTAINER host_pid=%d'%(101+role),
                'CIS_BLOCK_BEGIN role=%d major=8 minor=%d start_ns=10'%(role,16 if private and role else 0)]
            for n in range(8):
                rows.append('CIS_BLOCK_IO role=%d iteration=%d op=%s offset=%d before_ns=%d after_ns=%d bytes=4096 verified=1'%(
                    role,n//2,('write','read')[n%2],(1+role*8+n//2)*4096,10+n*10,15+n*10))
            rows.append('CIS_BLOCK_DONE operations=8 errors=0'); result.append('\n'.join(rows))
        return result

    def test_frozen_alternation(self):
        rows=case_order(); self.assertEqual(len(rows),12)
        self.assertEqual(rows[:2],['shared-off-r1','shared-block-r1'])
        self.assertEqual(rows[4:6],['shared-block-r2','shared-off-r2'])

    def test_device_selection_and_failed_io(self):
        window=dict(start_ns=0,end_ns=100)
        self.assertEqual(check_case('shared',window,self.logs())['status'],'PASS')
        self.assertEqual(check_case('private',window,self.logs(True))['status'],'PASS')
        self.assertEqual(check_case('private',window,self.logs())['status'],'FAIL')
        logs=self.logs(); logs[0]=logs[0].replace('verified=1','verified=0',1)
        self.assertEqual(check_case('shared',window,logs)['status'],'FAIL')

    def test_zero_coverage_cannot_pass(self):
        report=dict(quality=dict(status='PASS'),scope_audit=dict(status='PASS'),requests=[])
        result=check_case('shared',dict(start_ns=0,end_ns=100),self.logs(),report,
            [dict(id=1,generation=1),dict(id=2,generation=1)])
        self.assertEqual(result['status'],'FAIL')

    def test_full_pid_tid_truth_and_device_byte_pairing(self):
        rows=[]
        for role in range(2):
            for n in range(8):
                start=11+n*10; pid=101+role
                rows.append(dict(submitter=[role+1,1,(pid<<32)|pid,1],episode_ns=start,
                    request=1000+role*100+n,terminal='data_completion',episode_interval_ns=[start,start+2],
                    devices=[[8,0]],operation=(1,0)[n%2],initial_bytes=4096,
                    completions=[dict(bytes=4096,status=0)],uncertainty={},blocking_container=None))
        report=dict(quality=dict(status='PASS'),scope_audit=dict(status='PASS'),requests=rows)
        identities=[dict(id=1,generation=1),dict(id=2,generation=1)]
        result=check_case('shared',dict(start_ns=0,end_ns=100),self.logs(),report,identities)
        self.assertEqual(result['status'],'PASS',result)
        rows[0]['submitter'][2]=101
        self.assertEqual(check_case('shared',dict(start_ns=0,end_ns=100),self.logs(),report,identities)['status'],'FAIL')

    def test_fixture_counters_are_independent_of_capture(self):
        before={key:9 for key in COUNTERS}
        for mode in ('requeue','partial'):
            increments=dict(requests=16,requeues=16 if mode=='requeue' else 0,
                partials=16 if mode=='partial' else 0,completions=16,errors=0)
            after={key:before[key]+increments[key] for key in COUNTERS}
            self.assertEqual(check_counters(mode,before,after)['status'],'PASS')
            after['errors']+=1
            self.assertEqual(check_counters(mode,before,after)['status'],'FAIL')
        with self.assertRaises(ValueError): check_counters('partial',{},before)
        with self.assertRaises(ValueError): check_counters('unknown',before,before)

    def test_real_request_phase_contract_cannot_pass_missing_events(self):
        identities=[dict(id=1,generation=1),dict(id=2,generation=1)]
        for mode in ('requeue','partial'):
            rows=[]
            for role in range(2):
                for n in range(8):
                    lo=11+n*10; pid=101+role
                    ends=['requeue','data_completion'] if mode=='requeue' else ['data_completion']
                    sizes=[2048,2048] if mode=='partial' else [4096]
                    rows.append(dict(submitter=[role+1,1,(pid<<32)|pid,1],episode_ns=lo,
                        request=1000+role*100+n,terminal='data_completion',episode_interval_ns=[lo,lo+2],
                        devices=[[8,0]],operation=(1,0)[n%2],initial_bytes=4096,
                        service_intervals=[dict(end=end) for end in ends],
                        completions=[dict(bytes=size,status=0) for size in sizes],
                        head_bio_origins=[dict(registered_container=[role+1,1],cgroup_id=role+1,
                            bytes=left,request_remaining_bytes=left,ancestor_overdepth=False)
                            for left in ([4096,2048] if mode=='partial' else [4096])],
                        uncertainty={},blocking_container=None))
            report=dict(quality=dict(status='PASS'),scope_audit=dict(status='PASS'),requests=rows)
            result=check_case('shared',dict(start_ns=0,end_ns=100),self.logs(),report,identities,
                fixture=mode,verify_blkcg=True)
            self.assertEqual(result['status'],'PASS',result)
            rows[0]['head_bio_origins'][0]['bytes']=8192
            self.assertEqual(check_case('shared',dict(start_ns=0,end_ns=100),self.logs(),report,identities,
                fixture=mode,verify_blkcg=True)['status'],'FAIL')
            rows[0]['head_bio_origins'][0]['bytes']=4096
            if mode=='requeue': rows[0]['service_intervals'].pop(0)
            else: rows[0]['completions']=[dict(bytes=4096,status=0)]
            self.assertEqual(check_case('shared',dict(start_ns=0,end_ns=100),self.logs(),report,identities,fixture=mode)['status'],'FAIL')
