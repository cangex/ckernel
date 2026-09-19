# SPDX-License-Identifier: GPL-2.0
import copy
import unittest
from allocator_rollback_check import check_case, case_order


class RollbackTruth(unittest.TestCase):
    def example(self, case='partial'):
        rows=[]; calls=[]; frees=[]
        for actor in range(2):
            truth=[]
            for index,action in enumerate((1,2,2,3)):
                armed=int(case=='partial' and actor==0 and index==1)
                objects=([10,11,0,0] if index==0 else [10,0,0,0] if index==3 else
                         [11,0,0,0] if armed else [11,12,13,14])
                r=dict(index=index,action=action,cache=actor,armed=armed,cpu=actor,
                       cache_address=100+actor,begin_ns=1000+index*100,end_ns=1090+index*100,
                       returned=0 if armed or index in (0,3) else 4,
                       populated=1 if armed else 4 if index in (1,2) else 0,
                       **{'object%d'%j:o for j,o in enumerate(objects)})
                truth.append(r)
                if actor or index==3: continue
                for j in range(2 if index==0 else 1):
                    c=dict(actor=[1,1,20,99],interval_ns=[r['begin_ns']+1+j*5,r['end_ns']-20+j],
                           call_ns=r['begin_ns']+1+j*5,cache_address=100,sample_shift=0,
                           object_address=objects[j] if index==0 else None,
                           operation='single' if index==0 else 'bulk',requested=1 if index==0 else 4,
                           returned_count=r['returned'],rolled_back_count=1 if armed else 0,
                           object_samples=[dict(object=o) for o in objects if o],
                           result=dict(status='FAILED' if armed else 'RETURNED',
                                       failure_region='bulk_rollback' if armed else None,cause='UNKNOWN' if armed else None),
                           visits=dict(new_begin=1,bulk_rollback=1) if armed else {},holder=None)
                    calls.append(c)
                    if index in (1,2):
                        frees.extend(dict(allocation_requester=c['actor'],observation_key=dict(call_ns=c['call_ns']),
                                          object_address=o,release_entry_ns=r['end_ns']-5,
                                          release_cpu=0,allocation_state='rolled_back' if armed else 'returned') for o in objects if o)
            rows.append(truth)
        report=dict(calls=calls,lifetimes=dict(status='PASS',release_entries=frees,allocations_without_release=0),
                    quality=dict(status='PASS'),scope_audit=dict(status='PASS'),excluded={})
        return rows,report

    def verify(self, rows, report, case='partial'):
        logs=['CIS_SESSION_CONTAINER host_pid=%d\n'%(20+actor)+
              '\n'.join('CIS_ALLOC_ROLLBACK '+' '.join('%s=%s'%v for v in r.items()) for r in truth)
              for actor,truth in enumerate(rows)]
        return check_case(case,dict(start_ns=900,end_ns=1500),logs,report,[dict(id=1,generation=1),dict(id=2,generation=1)])

    def test_partial_and_unmarked(self):
        for case in ('partial','unmarked'):
            rows,report=self.example(case)
            result=self.verify(rows,report,case)
            self.assertEqual(result['status'],'PASS',result)
            self.assertEqual(result['captured'],4)

    def test_missing_prefix_release(self):
        rows,report=self.example(); report['lifetimes']['release_entries'].pop(0)
        self.assertEqual(self.verify(rows,report)['status'],'FAIL')

    def test_invented_blocker(self):
        rows,report=self.example(); report['calls'][2]['blocking_container']=[2,1]
        self.assertEqual(self.verify(rows,report)['status'],'FAIL')

    def test_wrong_failure_region(self):
        rows,report=self.example(); report['calls'][2]['result']['failure_region']='pre_allocation_hook'
        self.assertEqual(self.verify(rows,report)['status'],'FAIL')

    def test_invented_natural_pressure_cause(self):
        rows,report=self.example(); report['calls'][2]['result']['cause']='other_container'
        self.assertEqual(self.verify(rows,report)['status'],'FAIL')

    def test_release_after_call_boundary(self):
        rows,report=self.example(); report['lifetimes']['release_entries'][0]['release_entry_ns']=1499
        self.assertEqual(self.verify(rows,report)['status'],'FAIL')

    def test_unmarked_bystander_fails(self):
        rows,report=self.example(); rows[1][1]['returned']=0
        self.assertEqual(self.verify(rows,report)['status'],'FAIL')

    def test_private_call_leaks_into_selection(self):
        rows,report=self.example(); c=copy.deepcopy(report['calls'][0]); c['actor']=[2,1,21,99]
        report['calls'].append(c)
        self.assertEqual(self.verify(rows,report)['status'],'FAIL')

    def test_missing_returned_object(self):
        rows,report=self.example(); report['calls'][3]['object_samples'].pop()
        self.assertEqual(self.verify(rows,report)['status'],'FAIL')

    def test_frozen_opposite_order(self):
        self.assertEqual(len(case_order()),12)
        self.assertEqual(case_order()[:6],['partial-off0','partial-allocator0','partial-allocator1',
                                         'partial-off1','partial-off2','partial-allocator2'])


if __name__=='__main__': unittest.main()
