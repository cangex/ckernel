#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("owner", Path(__file__).resolve().parents[3]/"container_interference/owner_report.py")
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)


def event(t, phase, who, obj=100, epoch=10, flags=0, **extra):
    f = dict(sample_time_ns=t, phase=phase, actor_id=who, actor_generation=1,
             actor_tid=who+100, actor_start=who+1000, resource=1, object=obj,
             epoch=epoch, flags=flags, skipped=0, protocol=2,
             attempt_ns=who+10000 if phase in (2,3,12) else 0)
    f.update(extra)
    return {"kind": "OWNER", "detail": " ".join(f"{k}={v}" for k, v in f.items())}


class OwnerTests(unittest.TestCase):
    def test_distinct_profile_sessions_never_join(self):
        first=event(1,3,1); first['session_id']=1
        second=event(2,2,2); second['session_id']=2
        with self.assertRaises(ValueError): owner.analyze([first,second])

    def test_aborted_attempt_cannot_splice_to_later_trylock(self):
        r=[event(1,3,1),event(2,2,2),event(3,12,2,result=-4),
           event(10,4,1),event(20,3,2,attempt_ns=0)]
        out=owner.analyze(r)
        self.assertEqual([(e['begin_ns'],e['end_ns'],e['outcome']) for e in out['edges']],[(2,3,'aborted')])
        self.assertEqual(out['aborted_attempts'],1)
        self.assertEqual(out['edges'][0]['relation_type'],'holder_waiter')

    def test_repeated_failures_are_separate_attempts(self):
        r=[event(1,3,1),event(2,2,2,attempt_ns=2),event(3,12,2,attempt_ns=2,result=-4),
           event(4,2,2,attempt_ns=4),event(5,12,2,attempt_ns=4,result=-35),
           event(9,4,1),event(10,3,2,attempt_ns=0)]
        self.assertEqual([(e['begin_ns'],e['end_ns']) for e in owner.analyze(r)['edges']],[(2,3),(4,5)])

    def test_attempt_mismatch_and_missing_identifier_fail_closed(self):
        for attempt in (0,999):
            r=[event(1,3,1),event(2,2,2),event(3,4,1),event(4,3,2,attempt_ns=attempt)]
            self.assertFalse(owner.analyze(r)['edges'])

    def test_new_wait_does_not_reuse_cancelled_or_incomplete_wait(self):
        r=[event(1,3,1),event(2,2,2,attempt_ns=2),event(4,2,2,attempt_ns=4),
           event(6,4,1),event(7,3,2,attempt_ns=4)]
        self.assertEqual(owner.analyze(r)['edges'][0]['begin_ns'],4)

    def test_legacy_protocol_is_not_promoted(self):
        r=[event(1,3,1,protocol=1),event(2,2,2,protocol=1),event(3,4,1,protocol=1),event(4,3,2,protocol=1)]
        self.assertFalse(owner.analyze(r)['edges'])
        self.assertTrue(owner.analyze(r)['legacy_protocol'])

    def test_pid_reuse_and_container_migration_are_not_spliced(self):
        for identity in ({'actor_start':999},{'actor_generation':2},{'actor_id':3}):
            r=[event(1,3,1),event(2,2,2),event(3,4,1),event(4,3,2,**identity)]
            self.assertFalse(owner.analyze(r)['edges'])

    def test_unfinished_wait_at_window_end_has_no_fabricated_duration(self):
        r=[event(1,3,1),event(2,2,2),event(3,4,1)]
        self.assertFalse(owner.analyze(r)['edges'])
        self.assertGreater(owner.analyze(r)['incomplete_intervals'],0)

    def test_closed_and_handoff(self):
        r = [event(1,3,1),event(2,2,2),event(5,4,1),event(6,3,2),event(8,5,1),event(9,4,2)]
        out = owner.analyze(r[::-1])
        self.assertEqual([(e["holder"][0],e["overlap_ns"]) for e in out["edges"]], [(1,3)])

    def test_private_locks(self):
        self.assertFalse(owner.analyze([event(1,3,1),event(2,2,2,obj=200),event(3,4,1),event(4,3,2,obj=200)])["edges"])

    def test_snapshot_is_not_history(self):
        self.assertFalse(owner.analyze([event(2,2,2,holder_tid=101),event(3,4,1),event(4,3,2)])["edges"])

    def test_reuse_and_escape(self):
        for phase in (1,7,8):
            self.assertFalse(owner.analyze([event(1,3,1),event(2,2,2),event(3,phase,1),event(4,3,2),event(5,4,1)])["edges"])

    def test_preempt_is_not_spin_time(self):
        r=[event(1,3,1),event(2,2,2),event(3,9,1,flags=1),event(7,10,1),event(8,4,1),event(9,3,2)]
        edge=owner.analyze(r)["edges"][0]
        self.assertEqual(edge["overlap_ns"],6)
        self.assertEqual(edge["holder_offcpu"][0]["ns"],4)
        self.assertEqual(edge["holder_offcpu"][0]["reason"],"preempted")

    def test_loss_downgrades(self):
        r=[event(1,3,1),event(2,2,2),event(3,4,1),event(4,3,2),{"kind":"buffer_loss"}]
        self.assertEqual(owner.analyze(r)["edges"][0]["level"],"INCOMPLETE")

    def test_stale_release_and_task_reuse(self):
        r=[event(1,3,1),event(2,2,2),event(3,3,3),event(4,4,1),event(5,3,2)]
        self.assertFalse(owner.analyze(r)["edges"])

    def test_wait_across_two_holders_is_split(self):
        r=[event(1,3,1),event(2,2,3),event(4,4,1),event(5,3,2),event(8,4,2),event(9,3,3)]
        self.assertEqual([(e["holder"][0],e["overlap_ns"]) for e in owner.analyze(r)["edges"]],[(1,2),(2,3)])

    def test_address_reused_in_new_epoch(self):
        r=[event(1,3,1),event(2,2,2,epoch=20),event(3,4,1),event(4,3,2,epoch=20)]
        self.assertFalse(owner.analyze(r)["edges"])

    def test_limit_keeps_closed_prefix_not_pending_tail(self):
        r=[event(1,3,1),event(2,2,2),event(3,4,1),event(4,3,2),event(5,2,1),event(6,11,2),event(7,4,2),event(8,3,1)]
        out=owner.analyze(r)
        self.assertEqual(len(out["edges"]),1)
        self.assertEqual(out["bounded_prefix_limits"],1)

    def test_stack_export_is_joined_without_inventing_missing_symbols(self):
        r=[event(1,3,1),event(2,2,2,stack_id=7),event(3,4,1),event(4,3,2),
           {"kind":"stack","detail":"stack_id=7 ips=abcd,ef01"},
           {"kind":"stack_symbols","detail":"stack_id=7 leaf_to_root=lockref_get>dget>caller"}]
        edge=owner.analyze(r)["edges"][0]
        self.assertEqual(edge["waiter_stack_ips"],["abcd","ef01"])
        self.assertEqual(edge["waiter_stack_leaf_to_root"],["lockref_get","dget","caller"])


if __name__ == "__main__":
    unittest.main()
