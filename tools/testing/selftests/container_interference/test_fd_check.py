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


if __name__=='__main__': unittest.main()
