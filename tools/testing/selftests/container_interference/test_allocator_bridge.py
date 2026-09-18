# SPDX-License-Identifier: GPL-2.0
import unittest
from allocator_vm_check import check_work


class AllocatorBridge(unittest.TestCase):
    def logs(self):
        return ['CIS_SESSION_CONTAINER host_pid=%d\n'%pid+''.join(
            'CIS_ALLOC_OP index=%d begin_ns=%d end_ns=%d split_regions=128 success=1\n'%(i,10+i*10,19+i*10)
            for i in range(8)) for pid in (101,102)]

    def report(self):
        return dict(quality={'status':'PASS'},scope_audit={'status':'PASS'},calls=[
            dict(actor=[i,1,(pid<<32)|pid,2],interval_ns=[11,15],sample_shift=6,
                 stack_leaf_to_root=['mt_alloc_one'],phases=[]) for i,pid in ((1,101),(2,102))])

    def test_no_inferred_recall_and_wrong_task_rejected(self):
        window=dict(start_ns=0,end_ns=100)
        ids=[dict(id=1,generation=1),dict(id=2,generation=1)]
        r=check_work(window,self.logs(),self.report(),ids)
        self.assertEqual(r['status'],'PASS'); self.assertIsNone(r['recall'])
        report=self.report(); report['calls'][1]['actor'][2]=200
        self.assertEqual(check_work(window,self.logs(),report,ids)['status'],'FAIL')

    def test_missing_launch_identity_or_out_of_window_fails(self):
        logs=self.logs(); logs[0]='\n'.join(logs[0].splitlines()[1:])
        self.assertEqual(check_work(dict(start_ns=0,end_ns=100),logs)['status'],'FAIL')
        self.assertEqual(check_work(dict(start_ns=0,end_ns=50),self.logs())['status'],'FAIL')
