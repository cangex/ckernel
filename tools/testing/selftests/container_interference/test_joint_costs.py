# SPDX-License-Identifier: GPL-2.0
import copy
from pathlib import Path
import tempfile
import unittest
from joint_costs import PF_KTHREAD,analyze,cgroup_cost,kernel_threads,meminfo,task_stat


class JointCosts(unittest.TestCase):
    def cg(self,n=0):
        return {'cpu.stat':'usage_usec %d\nuser_usec %d\nsystem_usec %d\n'%(100+n,50+n,50),
            'memory.current':str(4096-n),'memory.peak':'8192',
            'memory.stat':'anon 1024\nslab 2048\nslab_reclaimable 512\n',
            'memory.events':'low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n'}

    def snapshot(self,n=0):
        thread=dict(pid=17,name='worker',flags=PF_KTHREAD,user_ticks=1,system_ticks=2+n,start_ticks=9)
        return dict(time_ns=100+n*100,read_end_ns=130+n*100,
            roots=[self.cg(n) for unused in range(4)],management=self.cg(n),
            kthreads=dict(start_ns=110+n*100,end_ns=120+n*100,limit=4096,scanned=10,
                races=0,capped=False,tasks={'17:9':thread}),
            memory='MemFree: %d kB\nSlab: 100 kB\nSReclaimable: 30 kB\n'%(500-n))

    def stat(self,pid=17):
        fields=['S']+['0']*19
        for index,value in ((6,PF_KTHREAD),(11,3),(12,7),(19,99)): fields[index]=str(value)
        return '%d (worker with ) chars) '%pid+' '.join(fields)

    def test_task_stat_uses_right_parenthesis_and_native_fields(self):
        row=task_stat(self.stat())
        self.assertEqual(row['name'],'worker with ) chars')
        self.assertEqual((row['user_ticks'],row['system_ticks'],row['start_ticks']),(3,7,99))
        self.assertTrue(row['flags'] & PF_KTHREAD)
        for text in ('17 no brackets','17 (name) S 0','-1 (name) '+'0 '*20):
            with self.assertRaises(ValueError): task_stat(text)

    def test_bounded_scan_records_cap_and_read_races(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for pid in (17,18,19):
                (root/str(pid)).mkdir(); (root/str(pid)/'stat').write_text(self.stat(pid))
            result=kernel_threads(root,limit=1)
            self.assertEqual(result['scanned'],1); self.assertTrue(result['capped'])
            self.assertEqual(len(result['tasks']),1)
            (root/'20').mkdir()
            result=kernel_threads(root)
            self.assertEqual(result['races'],1); self.assertEqual(len(result['tasks']),3)

    def test_scope_has_no_exclusive_cpu_or_additive_memory_claim(self):
        result=analyze(self.snapshot(),self.snapshot(1),100)
        self.assertEqual(result['kernel_threads']['matched_cpu_ticks'],1)
        self.assertEqual(result['kernel_threads']['tick_resolution_ns'],10_000_000)
        self.assertEqual(result['management']['cpu_delta_usec']['usage_usec'],1)
        self.assertEqual(result['memory_delta_bytes']['MemFree'],-1024)
        self.assertFalse(result['observer_total_cpu_known'])
        self.assertFalse(result['observer_total_kernel_memory_known'])
        self.assertNotIn('total_bytes',result)

    def test_pid_reuse_is_not_a_join_and_churn_stays_visible(self):
        before,after=self.snapshot(),self.snapshot(1)
        row=after['kthreads']['tasks'].pop('17:9'); row['start_ticks']=10
        after['kthreads']['tasks']['17:10']=row
        result=analyze(before,after,100)['kernel_threads']
        self.assertEqual(result['matched'],[])
        self.assertEqual(result['new_keys'],['17:10']); self.assertEqual(result['gone_keys'],['17:9'])

    def test_bad_identity_regression_and_boundaries_reject(self):
        for path,value in ((('kthreads','tasks','17:9','flags'),0),
                           (('kthreads','tasks','17:9','start_ticks'),10),
                           (('kthreads','tasks','17:9','system_ticks'),0),
                           (('kthreads','limit'),8192),(('read_end_ns',),210)):
            after=self.snapshot(1); node=after
            for part in path[:-1]: node=node[part]
            node[path[-1]]=value
            with self.assertRaises(ValueError): analyze(self.snapshot(),after,100)

    def test_memory_current_may_drop_but_peaks_do_not_reset(self):
        self.assertEqual(cgroup_cost(self.cg(),self.cg(1))['memory_current_start_end_bytes'],[4096,4095])
        after=self.cg(1); after['memory.peak']='0'
        with self.assertRaises(ValueError): cgroup_cost(self.cg(),after)
        after=self.cg(1); after['cpu.stat']='usage_usec 0\nuser_usec 0\nsystem_usec 0\n'
        with self.assertRaises(ValueError): cgroup_cost(self.cg(),after)
        with self.assertRaises(ValueError): meminfo('Slab: 200 MB\n')
        with self.assertRaises(ValueError): meminfo('Slab: 1 kB\nSlab: 2 kB\n')
