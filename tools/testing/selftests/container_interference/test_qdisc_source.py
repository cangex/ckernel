# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import unittest
from source_switches import expected_fields

ROOT=Path(__file__).resolve().parents[4]


class QueueSourceTests(unittest.TestCase):
    def test_independent_source_off_and_private_socket_off(self):
        off=expected_fields('19',None)
        self.assertTrue(all(v=='0' for k,v in off.items() if k!='version'))
        active=expected_fields('19','qdisc')
        self.assertEqual({k for k,v in active.items() if v=='1'}, {'qdisc','qdisc_filter'})
        with self.assertRaises(ValueError): expected_fields('18','qdisc')

    def test_no_skb_layout_or_hot_owner_map(self):
        text=(ROOT/'kernel/locking/cis_qdisc.c').read_text()
        begin=text.split('void __cis_qdisc_begin(',1)[1].split('EXPORT_SYMBOL_GPL(__cis_qdisc_begin)',1)[0]
        end=text.split('void __cis_qdisc_end(',1)[1].split('EXPORT_SYMBOL_GPL(__cis_qdisc_end)',1)[0]
        for forbidden in ('mutex_lock','kmalloc','kzalloc','atomic_inc','skb->'):
            if forbidden!='skb->': self.assertNotIn(forbidden,begin)
            self.assertNotIn(forbidden,end)
        self.assertIn('in_serving_softirq()',begin)
        self.assertNotIn('in_interrupt()',begin)
        self.assertIn('qdisc_refcount_inc(q)',text)
        self.assertIn('qdisc_put(f->qdisc)',text)
        self.assertIn('synchronize_rcu()',text)

    def test_retire_hook_precedes_reset(self):
        text=(ROOT/'net/sched/sch_generic.c').read_text().split('void qdisc_reset(',1)[1].split('EXPORT_SYMBOL(qdisc_reset)',1)[0]
        self.assertLess(text.index('cis_qdisc_invalidate(qdisc)'),text.index('ops->reset(qdisc)'))
        change=(ROOT/'net/sched/sch_api.c').read_text().split('static int qdisc_change(',1)[1].split('struct check_loop_arg',1)[0]
        self.assertLess(change.index('cis_qdisc_invalidate(sch)'),change.index('sch->ops->change(sch,'))


if __name__=='__main__': unittest.main()
