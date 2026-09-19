# SPDX-License-Identifier: GPL-2.0
import unittest
from pathlib import Path
import test_net_report
from net_backlog_check import check_tx


class NetTx(unittest.TestCase):
    def row(self,time,phase,begin=10,who=1,skb=77,**changes):
        d=dict(protocol=1,sample_time_ns=time,phase=phase,begin_ns=begin,backend_ns=begin+5,
               tid=100+who,task_start=1,skb=skb,cookie=20+who,socket=30+who,context=0,
               actor_tid=100+who,actor_start=1,actor_id=who,actor_generation=1,
               cpu=0,netns=9,gfp=1,requested=256,stack_id=-1)
        d.update(changes)
        return dict(session_id='7',kind='NET_TX',id=who,generation=1,
                    detail=' '.join('%s=%s'%p for p in d.items()))

    def run_rows(self,rows,record=None):
        return test_net_report.NetReport().run_rows(rows,record)

    def good(self):
        return [self.row(15,1),self.row(20,2),self.row(40,5)]

    def test_backend_and_release_not_blocking_or_payload_owner(self):
        r=self.run_rows(self.good()); self.assertEqual(r['quality']['status'],'PASS',r)
        e=r['tx']['episodes'][0]
        self.assertEqual(e['backend_wall_ns'],5)
        self.assertEqual(e['requester'],[1,1,101,1]); self.assertEqual(e['release_entry_ns'],40)
        self.assertEqual(e['packet_payload_owner'],'UNKNOWN')
        self.assertIsNone(e['backend_cpu_ns']); self.assertIsNone(e['blocking_container'])

    def test_release_executor_not_requester_and_irq_not_interrupted_task(self):
        for change,expected in ((dict(actor_id=2,actor_tid=102),[2,1,102,1]),
            (dict(context=1,actor_id=0,actor_generation=0,actor_tid=0,actor_start=0),None)):
            rows=self.good()[:2]+[self.row(40,5,**change)]
            e=self.run_rows(rows)['tx']['episodes'][0]
            self.assertEqual(e['requester'],[1,1,101,1]); self.assertEqual(e['release_executor'],expected)

    def test_private_and_sequential_address_reuse(self):
        rows=self.good()+[self.row(55,1,begin=50,who=2),self.row(60,2,begin=50,who=2),self.row(80,5,begin=50,who=2)]
        r=self.run_rows(rows)
        self.assertEqual(len(r['tx']['episodes']),2,r)
        self.assertNotEqual(r['tx']['episodes'][0]['cookie'],r['tx']['episodes'][1]['cookie'])

    def test_backend_failure_and_admission_rejection(self):
        r=self.run_rows([self.row(15,4,skb=0)])
        self.assertEqual(r['tx']['episodes'][0]['outcome'],'BACKEND_ALLOCATION_FAILED')
        r=self.run_rows([self.row(15,1),self.row(18,5),self.row(20,3)])
        self.assertEqual(r['tx']['episodes'][0]['outcome'],'MEMORY_ADMISSION_REJECTED')

    def test_clone_or_other_address_not_inherited(self):
        r=self.run_rows(self.good()[:2]+[self.row(40,5,skb=78)])
        self.assertEqual(r['tx']['status'],'FAIL'); self.assertFalse(r['tx']['episodes'])

    def test_duplicate_wrong_order_identity_and_missing_allocation(self):
        cases=[self.good()+[self.row(40,5)], [self.row(20,2),self.row(40,5)],
               [self.row(15,1),self.row(20,2),self.row(40,5,backend_ns=16)],
               [self.row(15,1),self.row(18,5),self.row(20,2)],
               [self.row(15,1),self.row(20,3),self.row(40,5)],
               [self.row(15,1,context=1)], [self.row(15,1),self.row(20,2,actor_id=2)],
               [self.row(15,1),self.row(20,2),self.row(40,5,context=1,actor_id=1)]]
        for rows in cases:
            r=self.run_rows(rows); self.assertEqual(r['tx']['status'],'FAIL',r)
            self.assertFalse(r['tx']['episodes'])

    def test_reuse_without_observed_release_is_not_joinable(self):
        r=self.run_rows(self.good()[:2]+[self.row(55,1,begin=50,who=2),self.row(60,2,begin=50,who=2)])
        self.assertEqual(r['tx']['excluded'],{'address_reuse_without_release':1})

    def test_missing_terminal_or_release_remain_unknown(self):
        r=self.run_rows(self.good()[:1]); e=r['tx']['episodes'][0]
        self.assertEqual(e['outcome'],'UNOBSERVED'); self.assertIsNone(e['release_entry_ns'])
        self.assertEqual(r['tx']['unknown'],{'terminal_unobserved':1,'release_unobserved':1})

    def test_quality_gap_drops_accepted_looking_lifetimes(self):
        record=test_net_report.NetReport().record(); record['receipt']['producer_recursion']['skipped']=1
        r=self.run_rows(self.good(),record)
        self.assertFalse(r['tx']['episodes']); self.assertEqual(r['quality']['status'],'FAIL')

    def test_source_uses_original_reference_and_no_clone_inheritance(self):
        root=Path(__file__).resolve().parents[4]
        bpf=(root/'tools/container_interference/bpf/net_tx.bpf.h').read_text()
        self.assertIn('BPF_NOEXIST',bpf)
        self.assertIn('bpf_map_delete_elem(&net_tx_live, &skb)',bpf)
        self.assertNotIn('skb_clone',bpf)
        source=(root/'net/ipv4/tcp.c').read_text()
        self.assertLess(source.index('cis_net_tx_step(&cis_sample, skb, skb ?'),
                        source.index('mem_scheduled = sk_wmem_schedule'))
        self.assertIn('CIS_TX_REJECTED',source)

    def test_independent_send_truth_and_wrong_container_cookie_or_interval(self):
        r=self.run_rows(self.good())
        sends=[dict(cookie=21,begin_ns=9,end_ns=21)]
        self.assertEqual(check_tx(sends,101,dict(id=1,generation=1),r)['status'],'PASS')
        for args in (([dict(cookie=22,begin_ns=9,end_ns=21)],101,dict(id=1,generation=1)),
                     (sends,102,dict(id=1,generation=1)),(sends,101,dict(id=2,generation=1)),
                     ([dict(cookie=21,begin_ns=11,end_ns=21)],101,dict(id=1,generation=1))):
            self.assertEqual(check_tx(*args,r)['status'],'FAIL')

    def test_unclosed_or_released_unobserved_truth_not_pass(self):
        for rows in (self.good()[:1],self.good()[:2]):
            r=self.run_rows(rows)
            self.assertEqual(check_tx([dict(cookie=21,begin_ns=9,end_ns=21)],101,dict(id=1,generation=1),r)['status'],'FAIL')


if __name__=='__main__': unittest.main()
