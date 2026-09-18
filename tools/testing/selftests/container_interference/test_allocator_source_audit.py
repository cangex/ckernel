# SPDX-License-Identifier: GPL-2.0
import unittest
from allocator_source_audit import delta


class AllocatorAudit(unittest.TestCase):
    def snapshot(self,n=0):
        return dict(time_ns=n,source_audit='version=1 active=0 shift=6 cache=maple_node snapshot=non_atomic bytes_per_cpu=48\n'
            'cpu=0 entries=%d eligible=%d sampled=%d steps=%d capped=0 irq_filtered=%d\n'%(100*n,64*n,n,10*n,n))

    def test_filter_work_is_not_bpf_delivery(self):
        r=delta(self.snapshot(),self.snapshot(1))
        self.assertEqual(r['totals']['entries'],100)
        self.assertEqual(r['totals']['sampled'],1)
        self.assertEqual(r['declared_counter_bytes'],48)

    def test_missing_irq_bad_boundary_or_config_fails(self):
        for change in ('irq_filtered=1','active=0','cache=maple_node'):
            b=self.snapshot(1)
            b['source_audit']=b['source_audit'].replace(change,'')
            with self.assertRaises(ValueError): delta(self.snapshot(),b)
        with self.assertRaises(ValueError): delta(self.snapshot(2),self.snapshot(1))

    def test_release_source_cost_and_incomplete_switch_rejected(self):
        snapshots=[]
        for n in (0,1):
            row=self.snapshot(n)
            row['source_audit']=row['source_audit'].replace('version=1 active=0','version=2 active=0 release_active=0').replace('bytes_per_cpu=48','bytes_per_cpu=72')
            row['source_audit']=row['source_audit'].rstrip()+' free_entries=%d free_items=%d free_capped=0\n'%(100*n,5*n)
            snapshots.append(row)
        result=delta(*snapshots)
        self.assertEqual(result['totals']['free_entries'],100)
        self.assertEqual(result['declared_counter_bytes'],72)
        snapshots[1]['source_audit']=snapshots[1]['source_audit'].replace('release_active=0','release_active=1')
        with self.assertRaises(ValueError): delta(*snapshots)
