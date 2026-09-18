# SPDX-License-Identifier: GPL-2.0
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'container_interference'))
from fd_check import check


class FDTruthCheck(unittest.TestCase):
    def fixture(self):
        logs=[]
        for container in range(2):
            rows=[]
            for thread in range(2):
                for operation in range(16):
                    base=1000+operation*1000+thread*100
                    if container==thread==operation==0: times=(100,110,200,210)
                    elif container==operation==0 and thread==1: times=(120,220,300,310)
                    else: times=(base,base+10,base+20,base+30)
                    rows.append(dict(zip(('begin_ns','acquired_ns','release_begin_ns','released_ns'),times),
                                     tid=thread+1,tgid=42+container,cgroup_id=7+container,object=10+container,files=20+container))
            logs.append('\n'.join('CIS_FD_TRUTH '+json.dumps(row) for row in rows)+'\nCIS_FD_DONE '+
                        json.dumps(dict(threads=2,operations_per_thread=16,native=0,failed=0)))
        edge=dict(resource='files_struct_lock',relation='container_internal',process_scope='same_tgid',
                  object='0xa',holder=[7,1,(42<<32)|1,1],waiter=[7,1,(42<<32)|2,2],
                  wait_begin_ns=125,wait_end_ns=219,begin_ns=125,end_ns=199)
        return dict(quality=dict(status='PASS'),findings=[edge]),logs

    def test_independent_truth_supports_only_matching_actor_and_overlap(self):
        report,logs=self.fixture()
        self.assertEqual(check(report,logs,'threads')['status'],'PASS')
        for mutation in ({'object':'0xb'},{'holder':[7,1,(42<<32)|99,1]},
                         {'wait_end_ns':999},{'relation':'cross_container'}):
            changed=copy.deepcopy(report);changed['findings'][0].update(mutation)
            self.assertEqual(check(changed,logs,'threads')['status'],'FAIL')

    def test_missing_positive_or_bad_quality_cannot_pass(self):
        report,logs=self.fixture();report['findings']=[]
        self.assertIn('missing_positive',check(report,logs,'threads')['errors'])
        report,logs=self.fixture();report['quality']['status']='BLOCKED'
        self.assertIn('capture_quality',check(report,logs,'threads')['errors'])

    def test_real_shared_table_needs_distinct_actors_and_same_object(self):
        report,original=self.fixture();logs=[]
        for container,text in enumerate(original):
            rows=[json.loads(line.split(' ',1)[1]) for line in text.splitlines() if line.startswith('CIS_FD_TRUTH ')]
            rows=[row for row in rows if row['tid']==1]
            for row in rows: row.update(object=10,files=20)
            if container: rows[0].update(begin_ns=120,acquired_ns=220,release_begin_ns=300,released_ns=310)
            logs.append('\n'.join('CIS_FD_TRUTH '+json.dumps(row) for row in rows)+'\nCIS_FD_DONE '+
                        json.dumps(dict(threads=1,operations_per_thread=16,native=0,failed=0))+
                        '\nCIS_FD_SHARED '+json.dumps(dict(pidns_init=1,explicit_clone_files=True,error=0)))
        edge=report['findings'][0]
        edge.update(relation='cross_container',process_scope='different_tgid',waiter=[8,1,(43<<32)|1,2])
        self.assertEqual(check(report,logs,'cross')['status'],'PASS')
        self.assertEqual(check(report,[logs[0],logs[1].replace('"files": 20','"files": 21')],'cross')['status'],'FAIL')
        edge['relation']='container_internal'
        self.assertEqual(check(report,logs,'cross')['status'],'FAIL')

    def test_reused_address_requires_disjoint_lifetimes_not_cross_generation_join(self):
        report,original=self.fixture();logs=[]
        for generation in range(4):
            for text in original:
                rows=[json.loads(line.split(' ',1)[1]) for line in text.splitlines() if line.startswith('CIS_FD_TRUTH ')]
                for row in rows:
                    row['tgid']+=generation*10
                    for name in ('begin_ns','acquired_ns','release_begin_ns','released_ns'): row[name]+=generation*100000
                logs.append('\n'.join('CIS_FD_TRUTH '+json.dumps(row) for row in rows)+'\nCIS_FD_DONE '+
                            json.dumps(dict(threads=2,operations_per_thread=16,native=0,failed=0)))
        result=check(report,logs,'reuse')
        self.assertEqual(result['status'],'PASS')
        self.assertEqual(result['observed_address_reuses'],6)
        report['findings'][0]['holder']=[7,1,(52<<32)|1,1]
        self.assertEqual(check(report,logs,'reuse')['status'],'FAIL')


if __name__=='__main__': unittest.main()
