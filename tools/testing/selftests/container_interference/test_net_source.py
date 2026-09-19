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

    def test_tx_callback_high_water_is_not_off_window_work(self):
        def snapshot(n):
            r=self.snapshot(0); r['time_ns']=n
            r['source_audit']=r['source_audit'].replace('version=1','version=2 tx_active=0').replace(
                'source_counter_bytes_per_cpu=40','source_counter_bytes_per_cpu=80').rstrip()+(
                    ' tx_entries=5 tx_selected=5 tx_callbacks=10 tx_callback_ns=100 tx_callback_max_ns=20\n')
            return r
        r=delta(snapshot(1),snapshot(2))
        self.assertFalse(any(r['totals'].values()))
        self.assertEqual(r['tx_callback_boot_max_ns'],20)
        self.assertEqual(r['counter_bytes'],80)
        self.assertEqual(expected_fields('14','net')['net_tx'],'1')
        self.assertEqual(expected_fields('14','allocator')['net_tx'],'0')

    def test_tx_unsupported_context_and_true_recursion_are_counted_separately(self):
        rows=[]
        for n in (0,1):
            r=self.snapshot(n)
            r['source_audit']=r['source_audit'].replace('version=1','version=3 tx_active=0').replace(
                'source_counter_bytes_per_cpu=40','source_counter_bytes_per_cpu=96').replace(
                'skipped=0','skipped=%d'%(2*n)).rstrip()+(
                    ' tx_entries=%d tx_selected=%d tx_callbacks=%d tx_callback_ns=%d tx_callback_max_ns=20'
                    ' tx_irq_skipped=%d tx_nested_skipped=%d\n'%(3*n,n,3*n,10*n,n,n))
            rows.append(r)
        result=delta(*rows)
        self.assertEqual(result['totals']['tx_irq_skipped'],1)
        self.assertEqual(result['totals']['tx_nested_skipped'],1)
        self.assertEqual(result['totals']['skipped'],2)
        rows[1]['source_audit']=rows[1]['source_audit'].replace('skipped=2','skipped=0')
        with self.assertRaises(ValueError): delta(*rows)

    def test_native_fast_and_callback_release_coverage(self):
        root=Path(__file__).resolve().parents[4]
        header=(root/'include/net/sock.h').read_text(); source=(root/'net/core/sock.c').read_text()
        self.assertIn('cis_net_event(sk, NULL, CIS_CN_RELEASED)',header)
        self.assertIn('cis_net_event(sk, NULL, CIS_CN_FAST_RELEASED)',header)
        self.assertEqual(source.count('cis_net_event(sk, NULL, CIS_CN_ACQUIRED)'),2)
        self.assertIn('cis_net_event(sk, NULL, CIS_CN_FAST_ACQUIRED)',source)
        native=(root/'kernel/locking/cis_observe.c').read_text().split('void __cis_net_event(',1)[1]
        self.assertIn('phase == CIS_CN_QUEUED || phase == CIS_CN_SERVICE_BEGIN',native)
        self.assertIn('sk->sk_protocol != IPPROTO_TCP || sk->sk_type != SOCK_STREAM',native)
        self.assertNotIn('phase == CIS_CN_SERVICE_END)',native)

    def test_process_only_tx_filter_never_erases_real_recursion(self):
        rows=[]
        for n in (0,1):
            r=self.snapshot(n)
            r['source_audit']=r['source_audit'].replace('version=1','version=4 tx_active=0').replace(
                'source_counter_bytes_per_cpu=40','source_counter_bytes_per_cpu=96').replace(
                'skipped=0','skipped=%d'%n).rstrip()+(
                    ' tx_entries=%d tx_selected=%d tx_callbacks=%d tx_callback_ns=%d tx_callback_max_ns=20'
                    ' tx_irq_filtered=%d tx_nested_skipped=%d\n'%(3*n,n,3*n,10*n,n,n))
            rows.append(r)
        result=delta(*rows)
        self.assertEqual(result['totals']['tx_irq_filtered'],1)
        self.assertEqual(result['totals']['tx_nested_skipped'],1)
        self.assertEqual(result['totals']['skipped'],1)
        rows[1]['source_audit']=rows[1]['source_audit'].replace(' skipped=1',' skipped=0')
        with self.assertRaises(ValueError): delta(*rows)
        source=(Path(__file__).resolve().parents[4]/'kernel/locking/cis_observe.c').read_text()
        begin=source.split('void __cis_net_tx_begin(',1)[1].split('EXPORT_SYMBOL',1)[0]
        irq=begin.split('if (in_interrupt()) {',1)[1].split('}',1)[0]
        nested=begin.split('if (this_cpu_read(cis_in_trace)) {',1)[1].split('}',1)[0]
        self.assertIn('cis_tx_irq_filtered',irq)
        self.assertNotIn('cis_skipped',irq)
        self.assertIn('cis_net_skipped',nested)
        self.assertIn('cis_skipped',nested)

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
        self.assertLess(accept.index('CIS_CN_ACCEPTED'),accept.rindex('return newfile;'))
        self.assertLess(accept.index('if (IS_ERR(newfile))'),accept.index('CIS_CN_ACCEPTED'))
        self.assertNotIn('CIS_CN_CREATED',accept)

    def test_origin_fixture_waits_inside_future_capture_window(self):
        root=Path(__file__).resolve().parents[4]
        workload=(root/'tools/testing/selftests/container_interference/net_workload.c').read_text()
        body=workload.split('int main(',1)[1]
        self.assertLess(body.index('until(start-300000000ULL)'),body.index('fd=transfer_socket('))
        harness=(root/'tools/testing/selftests/container_interference/net_vm.py').read_text()
        self.assertIn("window['start_ns']+500_000_000",harness)
        self.assertIn("+(['origin'] if origin else [])",harness)
