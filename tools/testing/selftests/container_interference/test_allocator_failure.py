# SPDX-License-Identifier: GPL-2.0
import copy
import unittest
from allocator_failure_check import check_case, expected, case_order, CASES


class FailureTruth(unittest.TestCase):
    ids=[dict(id=1,generation=1),dict(id=2,generation=1)]
    window=dict(start_ns=0,end_ns=1000)

    def example(self,case='single'):
        logs=[]; calls=[]; frees=[]
        for actor in range(2):
            text='CIS_SESSION_CONTAINER host_pid=%d\n'%(101+actor)
            for index in range(8):
                cache,armed,count,returned=expected(case,actor,index)
                b=10+index*100; obj=1000+actor*100+index; who=[actor+1,1,101+actor,9]
                r=dict(index=index,cache=cache,armed=armed,bulk=int(case=='bulk'),count=count,returned=returned,
                       result=0,cpu=actor,cache_address=99+cache,begin_ns=b,end_ns=b+20,
                       release_begin_ns=b+30 if returned else 0,release_end_ns=b+40 if returned else 0)
                text+='CIS_ALLOC_FAILURE '+' '.join('%s=%s'%x for x in r.items())+'\n'
                if returned: text+='CIS_ALLOC_FAILURE_OBJECT index=%d ordinal=0 object=%d\n'%(index,obj)
                if cache: continue
                calls.append(dict(actor=who,call_ns=b+1,interval_ns=[b+1,b+19],cache_address=99,
                    object_address=obj if returned else None,sample_shift=0,operation='bulk' if case=='bulk' else 'single',
                    requested=count,returned_count=returned,rolled_back_count=0,
                    visits=dict(begin=1,pre_begin=1,pre_end=1,end=1),object_samples=[]))
                if returned:
                    frees.append(dict(allocation_requester=who,observation_key={'call_ns':b+1},object_address=obj,
                                      release_cpu=actor,release_entry_ns=b+31))
            logs.append(text)
        return logs,dict(quality={'status':'PASS'},scope_audit={'status':'PASS'},excluded={},calls=calls,
                         lifetimes=dict(status='PASS',release_entries=frees))

    def test_five_cases_and_off(self):
        self.assertEqual(len(case_order()),30)
        for c in CASES:
            logs,r=self.example(c)
            result=check_case(c,self.window,logs,r,self.ids)
            self.assertEqual(result['status'],'PASS',result)
            self.assertEqual(result['selected_call_recall'],1)
            self.assertEqual(check_case(c,self.window,logs)['status'],'PASS')
            self.assertIsNone(check_case(c,self.window,logs)['selected_call_recall'])

    def test_failed_request_must_not_get_object_free_or_holder(self):
        for field,value in [('object_address',123),('returned_count',1),('rolled_back_count',1),('holder',[2,1]),
                            ('blocking_container',[2,1]),('object_samples',[{'object':123}]),('visits',{'begin':1,'end':1})]:
            logs,r=self.example(); r['calls'][0][field]=value
            self.assertEqual(check_case('single',self.window,logs,r,self.ids)['status'],'FAIL')
        logs,r=self.example(); r['lifetimes']['release_entries']=[dict(allocation_requester=[1,1,101,9],
            observation_key={'call_ns':11},object_address=1,release_cpu=0,release_entry_ns=40)]
        self.assertEqual(check_case('single',self.window,logs,r,self.ids)['status'],'FAIL')

    def test_private_and_bystander_controls_not_hidden(self):
        logs,r=self.example('private'); c=copy.deepcopy(r['calls'][0]); c['actor']=[2,1,102,9]; r['calls'].append(c)
        self.assertEqual(check_case('private',self.window,logs,r,self.ids)['status'],'FAIL')
        logs,r=self.example('bystander'); logs[1]=logs[1].replace('returned=1','returned=0')
        self.assertEqual(check_case('bystander',self.window,logs,r,self.ids)['status'],'FAIL')

    def test_lost_call_wrong_release_and_wrong_configuration_truth_rejected(self):
        logs,r=self.example(); r['calls'].pop()
        self.assertEqual(check_case('single',self.window,logs,r,self.ids)['status'],'FAIL')
        logs,r=self.example('recovery'); r['lifetimes']['release_entries'][0]['object_address']=1
        self.assertEqual(check_case('recovery',self.window,logs,r,self.ids)['status'],'FAIL')
        logs,r=self.example(); logs[0]=logs[0].replace('armed=1','armed=0')
        self.assertEqual(check_case('single',self.window,logs,r,self.ids)['status'],'FAIL')
