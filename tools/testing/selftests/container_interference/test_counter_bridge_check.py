# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'container_interference'))
from counter_bridge_check import check


class OrdinaryBridge(unittest.TestCase):
    def sample(self):
        record=dict(window=dict(start_ns=100,end_ns=1000))
        ops='\n'.join('CIS_MEM_OP index=%d begin_ns=%d end_ns=%d bytes=8388608 success=1'%(i,200+i*10,209+i*10) for i in range(16))
        log='CIS_SESSION_CONTAINER host_pid=20\n'+ops
        call=dict(actor=[1,2,20|(20<<32),100],interval_ns=[202,205],sample_shift=6,
                  stack_leaf_to_root=['page_counter_try_charge','try_charge_memcg'],elapsed_wall_ns=3)
        return record,dict(quality=dict(status='PASS'),calls=[call]),[log],[dict(id=1,generation=2)]

    def test_native_stack_and_identity(self):
        self.assertEqual(check(*self.sample())['status'],'PASS')
        record,report,logs,ids=self.sample(); report['calls'][0]['actor'][0]=99
        self.assertEqual(check(record,report,logs,ids)['status'],'FAIL')

    def test_no_truth_or_contention_claim(self):
        result=check(*self.sample())
        self.assertEqual(result['eligible_event_recall'],'UNAVAILABLE')
        self.assertEqual(result['cacheline_contention'],'UNVERIFIED')
        record,report,logs,ids=self.sample(); report['calls'][0]['stack_leaf_to_root']=['test_fixture']
        self.assertEqual(check(record,report,logs,ids)['status'],'FAIL')

    def test_operation_failures_and_outside_window_reject(self):
        record,report,logs,ids=self.sample(); logs=[logs[0].replace('success=1','success=0',1)]
        self.assertEqual(check(record,report,logs,ids)['status'],'FAIL')
        record,report,logs,ids=self.sample(); record['window']['end_ns']=300
        self.assertEqual(check(record,report,logs,ids)['status'],'FAIL')


if __name__=='__main__': unittest.main()
