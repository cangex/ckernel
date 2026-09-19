# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import unittest
from net_source_audit import delta
from source_switches import expected_fields


class NetSource(unittest.TestCase):
    def snapshot(self,n=0):
        return dict(time_ns=n,source_audit='version=1 active=0 release_active=0 shift=0 source_counter_bytes_per_cpu=40 snapshot=non_atomic\n'
            'cpu=0 entries=%d eligible=%d selected=%d releases=%d skipped=0\n'%(100*n,20*n,20*n,200*n))

    def test_entry_work_and_no_fictitious_total_cost(self):
        r=delta(self.snapshot(),self.snapshot(1))
        self.assertEqual(r['totals']['releases'],200); self.assertEqual(r['counter_bytes'],40)
        self.assertEqual(r['total_cost'],'UNKNOWN')
        self.assertEqual(expected_fields('5','net')['net_release'],'1')
        self.assertEqual(expected_fields('5','allocator')['net_release'],'0')
        with self.assertRaises(ValueError): expected_fields('4','net')

    def test_changed_source_or_counter_regression_fail(self):
        a,b=self.snapshot(),self.snapshot(1)
        b['source_audit']=b['source_audit'].replace('shift=0','shift=1')
        with self.assertRaises(ValueError): delta(a,b)
        with self.assertRaises(ValueError): delta(self.snapshot(1),self.snapshot())

    def test_native_fast_and_callback_release_coverage(self):
        root=Path(__file__).resolve().parents[4]
        header=(root/'include/net/sock.h').read_text(); source=(root/'net/core/sock.c').read_text()
        self.assertIn('cis_net_event(sk, NULL, CIS_CN_RELEASED)',header)
        self.assertIn('cis_net_event(sk, NULL, CIS_CN_FAST_RELEASED)',header)
        self.assertEqual(source.count('cis_net_event(sk, NULL, CIS_CN_ACQUIRED)'),2)
        self.assertIn('cis_net_event(sk, NULL, CIS_CN_FAST_ACQUIRED)',source)
        native=(root/'kernel/locking/cis_observe.c').read_text().split('void __cis_net_event(',1)[1]
        self.assertIn('phase == CIS_CN_QUEUED || phase == CIS_CN_SERVICE_BEGIN',native)
        self.assertNotIn('phase == CIS_CN_SERVICE_END)',native)

    def test_irq_actor_not_current_and_release_drops_observed_lifetime(self):
        root=Path(__file__).resolve().parents[4]
        text=(root/'tools/container_interference/bpf/cis.bpf.c').read_text()
        actor=text.split('void net_actor(',1)[1].split('void net_emit(',1)[0]
        self.assertIn('if (!context)',actor)
        free=text.split('int net_release(',1)[1].split('#endif',1)[0]
        self.assertIn('bpf_map_delete_elem(&net_skb, &skb)',free)
        self.assertNotIn('BPF_CORE_READ(sample, sk)',free)

    def test_create_after_security_and_accept_after_success(self):
        root=Path(__file__).resolve().parents[4]
        source=(root/'net/socket.c').read_text()
        create=source.split('int __sock_create(',1)[1].split('EXPORT_SYMBOL(__sock_create)',1)[0]
        self.assertLess(create.index('security_socket_post_create('),create.index('CIS_CN_CREATED'))
        self.assertIn('if (!kern && sock->sk)',create)
        accept=source.split('struct file *do_accept(',1)[1].split('static int __sys_accept4_file(',1)[0]
        self.assertLess(accept.index('move_addr_to_user('),accept.index('CIS_CN_ACCEPTED'))
        self.assertLess(accept.index('CIS_CN_ACCEPTED'),accept.index('return newfile;'))
        self.assertNotIn('CIS_CN_CREATED',accept)
