# SPDX-License-Identifier: GPL-2.0
import unittest
from pathlib import Path
import test_net_tx
from net_source_audit import delta


class NetRelease(unittest.TestCase):
    def row(self, time, phase, **changes):
        args=dict(protocol=3,release_ns=0,release_backend_ns=0,release_flags=0)
        if phase in (5,7):
            args.update(release_ns=40,release_flags=65)
        if phase==7:
            args.update(release_backend_ns=42,release_flags=65|256|512)
        args.update(changes)
        return test_net_tx.NetTx().row(time,phase,**args)

    def good(self):
        return [self.row(15,1),self.row(20,2),self.row(40,5),self.row(50,7)]

    def report(self, rows):
        return test_net_tx.NetTx().run_rows(rows)['tx']

    def test_backend_return_does_not_infer_blocker_cpu_or_physical_reclaim(self):
        result=self.report(self.good()); self.assertEqual(result['status'],'PASS',result)
        e=result['episodes'][0]
        self.assertEqual(e['release_backend_interval_ns'],[42,50])
        self.assertEqual(e['release_backend_wall_ns'],8)
        self.assertEqual(e['data_release_status'],'BACKEND_RETURNED')
        self.assertEqual(e['header_release_status'],'BACKEND_RETURNED')
        self.assertIsNone(e['backend_cpu_ns']); self.assertIsNone(e['blocking_container'])
        self.assertEqual(e['packet_payload_owner'],'UNKNOWN')

    def test_shared_clone_data_and_fclone_pair_retained_not_reclaimed(self):
        rows=self.good()[:2]+[self.row(40,5,release_flags=73),self.row(50,7,release_flags=73|2|4)]
        e=self.report(rows)['episodes'][0]
        self.assertEqual(e['data_release_status'],'SHARED_REFERENCE_RETAINED')
        self.assertEqual(e['header_release_status'],'FCLONE_PAIR_RETAINED')
        self.assertEqual(e['clone_lineage'],'UNOBSERVED')

    def test_gso_nonlinear_shape_is_not_payload_or_child_ownership(self):
        rows=self.good()[:2]+[self.row(40,5,release_flags=65|16|32),
                              self.row(50,7,release_flags=65|16|32|256|512)]
        e=self.report(rows)['episodes'][0]
        self.assertEqual(e['release_shape_flags'],64|16|32)
        self.assertEqual(e['packet_payload_owner'],'UNKNOWN')
        self.assertEqual(e['clone_lineage'],'UNOBSERVED')

    def test_missing_completion_does_not_promote_entry(self):
        r=self.report(self.good()[:-1]); self.assertEqual(r['status'],'PASS')
        self.assertEqual(r['unknown'],{'release_backend_unobserved':1})
        self.assertEqual(r['episodes'][0]['header_release_status'],'UNKNOWN')

    def test_bulk_napi_morph_entry_has_no_implied_backend(self):
        r=self.report(self.good()[:2]+[self.row(40,5,release_flags=0)])
        self.assertEqual(r['episodes'][0]['release_backend_status'],'UNOBSERVED')
        self.assertEqual(r['unknown'],{})

    def test_foreign_token_address_actor_and_flags_are_rejected(self):
        for changes in (dict(release_ns=39),dict(skb=78),dict(actor_id=2),
                        dict(release_flags=65|2|256|512),dict(release_flags=65),
                        dict(release_flags=65|4|512),dict(release_backend_ns=39),dict(protocol=2)):
            with self.subTest(changes=changes):
                r=self.report(self.good()[:-1]+[self.row(50,7,**changes)])
                self.assertEqual(r['status'],'FAIL',r); self.assertFalse(r['episodes'])

    def test_unmatched_duplicate_and_uninstrumented_completion(self):
        for rows in (self.good()+[self.row(50,7)],self.good()[:2]+[self.row(50,7)],
                     self.good()[:2]+[self.row(40,5,release_flags=0),self.row(50,7)]):
            self.assertEqual(self.report(rows)['status'],'FAIL')

    def test_irq_executor_and_requester_remain_distinct(self):
        irq=dict(context=1,actor_id=0,actor_generation=0,actor_tid=0,actor_start=0)
        e=self.report(self.good()[:2]+[self.row(40,5,**irq),self.row(50,7,**irq)])['episodes'][0]
        self.assertEqual(e['requester'],[1,1,101,1]); self.assertIsNone(e['release_executor'])

    def test_source_frozen_token_and_no_use_after_free(self):
        root=Path(__file__).resolve().parents[4]
        source=(root/'net/core/skbuff.c').read_text().split('void __kfree_skb(struct sk_buff *skb)',1)[1].split('EXPORT_SYMBOL',1)[0]
        self.assertIn('returned = kfree_skbmem(skb)',source)
        self.assertIn('cis_net_skb_release_end(&sample, returned)',source)
        bpf=(root/'tools/container_interference/bpf/net_tx.bpf.h').read_text().split('if (phase == 12)',1)[1].split('if (phase != 9)',1)[0]
        self.assertIn('release_start_ns',bpf); self.assertIn('net_tx_free',bpf)
        self.assertNotIn('net_tx_live',bpf); self.assertNotIn('identity(',bpf)

    def test_source_v5_cost_counters_and_backward_reader(self):
        def snapshot(n):
            return dict(time_ns=n,source_audit='version=5 active=0 release_active=0 tx_active=0 shift=0 source_counter_bytes_per_cpu=112 snapshot=non_atomic\n'
                'cpu=0 entries=0 eligible=0 selected=0 releases=%d skipped=0 tx_entries=0 tx_selected=0 tx_callbacks=0 tx_callback_ns=0 tx_callback_max_ns=0 tx_irq_filtered=0 tx_nested_skipped=0 release_ends=%d release_callback_ns=%d\n'%(n,n,10*n))
        r=delta(snapshot(1),snapshot(2))
        self.assertEqual(r['totals']['release_ends'],1)
        self.assertEqual(r['totals']['release_callback_ns'],10)
        self.assertEqual(r['counter_bytes'],112)


if __name__=='__main__': unittest.main()
