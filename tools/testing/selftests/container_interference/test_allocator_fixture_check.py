# SPDX-License-Identifier: GPL-2.0
import copy
import unittest
from allocator_fixture_check import check_case


class AllocatorTruth(unittest.TestCase):
    window = dict(start_ns=0,end_ns=1000)
    ids = [dict(id=1,generation=1),dict(id=2,generation=1)]

    def example(self,case='warm'):
        logs, calls, releases = [], [], []
        bulk = int(case in ('bulk','migration','rcu'))
        count = 8 if bulk else 1 if case=='cold' else 4
        for actor in range(2):
            cache = int(case=='private' and actor==1)
            log = 'CIS_SESSION_CONTAINER host_pid=%d\n' % (101+actor)
            for i in range(4):
                begin = 10+i*100
                actions = [3,1,2] if case=='cold' else [1,4,5] if case=='rcu' else [1,2]
                for action in actions:
                    b = begin-5 if action==3 else begin if action==1 else begin+40
                    row = dict(index=i,action=action,cache=cache,count=count if action==1 else 0,
                        bulk=0 if action in (3,4,5) else bulk,begin_ns=b,end_ns=b+30,cache_address=100+cache,
                        returned=0 if action==3 else count,cpu=actor+(2 if case=='migration' and action==2 else 0),result=0)
                    if action==5:
                        row.update(callback_begin_ns=begin+41,callback_end_ns=begin+50,callback_cpu=3,callback_context=1)
                    if action!=3:
                        row.update({'object%d'%j:1000+100*actor+count*i+j for j in range(count)})
                    log += 'CIS_ALLOC_TRUTH '+' '.join('%s=%s'%p for p in row.items())+'\n'
                if not cache:
                    for j in range(1 if bulk else count):
                        calls.append(dict(actor=[actor+1,1,101+actor,9],interval_ns=[begin+j*3,begin+j*3+2],
                            cache_address=100,sample_shift=0,operation='bulk' if bulk else 'single',
                            requested=count if bulk else 1,returned_count=count if bulk else 1,rolled_back_count=0))
                    for j in range(count):
                        releases.append(dict(allocation_requester=[actor+1,1,101+actor,9],
                            allocation_time_ns=begin+2,release_entry_ns=begin+42,object_address=1000+100*actor+count*i+j,
                            release_cpu=3 if case=='rcu' else actor+(2 if case=='migration' else 0),
                            release_executor=dict(context='softirq' if case=='rcu' else 'task')))
            logs.append(log)
        report = dict(quality={'status':'PASS'},scope_audit={'status':'PASS'},excluded={},calls=calls,
                      lifetimes=dict(status='PASS',release_entries=releases))
        return logs,report

    def test_five_positive_shapes_and_off(self):
        for case in ('cold','warm','bulk','private','migration'):
            logs,report=self.example(case)
            r=check_case(case,self.window,logs,report,self.ids)
            self.assertEqual(r['status'],'PASS',r)
            self.assertEqual(r['selected_call_recall'],1)
            self.assertIsNone(check_case(case,self.window,logs)['selected_call_recall'])

    def test_private_cache_and_wrong_pid_not_accepted(self):
        logs,report=self.example('private')
        bad=copy.deepcopy(report['calls'][0]); bad['actor']=[2,1,102,9]; bad['cache_address']=101
        report['calls'].append(bad)
        self.assertEqual(check_case('private',self.window,logs,report,self.ids)['status'],'FAIL')
        logs,report=self.example(); report['calls'][0]['actor'][2]=888
        self.assertEqual(check_case('warm',self.window,logs,report,self.ids)['status'],'FAIL')

    def test_partial_lost_wrong_count_and_window_rejected(self):
        for mutation in ('missing','lost','count','window','sampling'):
            logs,report=self.example('bulk')
            if mutation=='missing': report['calls'].pop()
            elif mutation=='lost': report['quality']['status']='FAIL'
            elif mutation=='count': report['calls'][0]['returned_count']=7
            elif mutation=='window': logs[0]=logs[0].replace('begin_ns=10','begin_ns=1001')
            else: report['calls'][0]['sample_shift']=6
            self.assertEqual(check_case('bulk',self.window,logs,report,self.ids)['status'],'FAIL')

    def test_free_executor_is_not_alloc_owner(self):
        logs,report=self.example('migration')
        result=check_case('migration',self.window,logs,report,self.ids)
        self.assertEqual(result['status'],'PASS')
        self.assertEqual(result['participants'][0]['free_attribution'],'NOT_OBSERVED')

    def test_actual_release_objects_and_rcu_callback_window(self):
        for case in ('cold','warm','bulk','private','migration','rcu'):
            logs,report=self.example(case)
            r=check_case(case,self.window,logs,report,self.ids,require_releases=True)
            self.assertEqual(r['status'],'PASS',r)
            self.assertEqual(check_case(case,self.window,logs,require_releases=True)['status'],'PASS')
        logs,report=self.example('rcu')
        report['lifetimes']['release_entries'][0]['release_executor']['context']='task'
        self.assertEqual(check_case('rcu',self.window,logs,report,self.ids,require_releases=True)['status'],'FAIL')
        logs,report=self.example('migration')
        report['lifetimes']['release_entries'][0]['object_address']=1
        self.assertEqual(check_case('migration',self.window,logs,report,self.ids,require_releases=True)['status'],'FAIL')
