# SPDX-License-Identifier: GPL-2.0
import unittest
from owner_test import event, owner


def row(t, phase, who, **extra):
    fields = dict(resource=4, cache=0xffff123400001000)
    fields.update(extra)
    return event(t, phase, who, **fields)


class SlubReport(unittest.TestCase):
    def test_complete_inner_overlap_identifies_node_and_cache(self):
        r = [row(1, 3, 1), row(2, 2, 2), row(4, 4, 1), row(6, 3, 2)]
        e = owner.analyze(r)['edges'][0]
        self.assertEqual(e['resource'], 'slub_node_list_lock')
        self.assertEqual(e['cache_address'], '0xffff123400001000')
        self.assertEqual(e['overlap_ns'], 2)
        self.assertEqual(e['wait_metric'], 'acquisition_attempt_wall_interval')
        self.assertFalse(e['causal'])

    def test_private_nodes_do_not_join(self):
        r = [row(1, 3, 1), row(2, 2, 2, obj=200), row(4, 4, 1), row(6, 3, 2, obj=200)]
        self.assertFalse(owner.analyze(r)['edges'])

    def test_cache_identity_change_or_absence_rejected(self):
        for cache in (0, 0xffff567800001000):
            r = [row(1, 3, 1), row(2, 2, 2, cache=cache), row(4, 4, 1), row(6, 3, 2)]
            result = owner.analyze(r)
            self.assertFalse(result['edges'])
            self.assertEqual(result['cache_identity_errors'], 1)

    def test_scheduler_flags_not_cache_and_not_spin_time(self):
        r = [row(1, 3, 1), row(2, 2, 2), row(3, 9, 1, flags=1),
             row(5, 10, 1, flags=0), row(6, 4, 1), row(7, 3, 2)]
        e = owner.analyze(r)['edges'][0]
        self.assertEqual(e['cache_address'], '0xffff123400001000')
        self.assertEqual(e['holder_offcpu'][0]['ns'], 2)

    def test_retire_reset_and_prefix_cannot_complete_pending_wait(self):
        for phase in (1, 7, 8, 11):
            r = [row(1, 3, 1), row(2, 2, 2), row(3, phase, 1), row(4, 4, 1), row(6, 3, 2)]
            self.assertFalse(owner.analyze(r)['edges'])

    def test_switching_holders_keeps_individual_intervals(self):
        r = [row(1, 3, 1), row(2, 2, 3), row(4, 4, 1), row(5, 3, 2), row(7, 4, 2), row(8, 3, 3)]
        self.assertEqual([(e['holder'][0], e['overlap_ns']) for e in owner.analyze(r)['edges']], [(1, 2), (2, 2)])

    def test_skipped_irq_or_recursion_is_not_e2(self):
        r = [row(1, 3, 1), row(2, 2, 2), row(4, 4, 1, skipped=1), row(6, 3, 2)]
        self.assertEqual(owner.analyze(r)['edges'][0]['level'], 'INCOMPLETE')

    def test_explicit_interrupt_barrier_cannot_bridge_ownership(self):
        r=[row(1,3,1),row(2,2,2),row(3,7,0,actor_id=0,actor_tid=0,actor_start=0),
           row(4,4,1),row(5,3,2),row(6,4,2),row(10,3,3),
           row(11,2,4),row(12,4,3),row(13,3,4)]
        out=owner.analyze(r)
        self.assertEqual([(e['waiter'][0],e['holder'][0]) for e in out['edges']],[(4,3)])
        self.assertEqual(out['slub_context_barriers'],1)
        self.assertFalse(out['loss_or_recursion_gap'])


if __name__ == '__main__':
    unittest.main()
