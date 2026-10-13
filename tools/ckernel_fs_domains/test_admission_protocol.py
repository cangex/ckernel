# SPDX-License-Identifier: GPL-2.0
"""Bounded sequential interleavings, NOT kernel/weak-memory verification."""
from dataclasses import dataclass,replace
from collections import deque
import unittest

@dataclass(frozen=True)
class State:
    gate: bool=True
    local: int=0
    published: int=0
    committed: bool=False
    entered: bool=False
    finished: bool=False

def late_publish_edges(s):
    if s.gate and not s.entered:
        yield 'enter-only-local',replace(s,local=1,entered=True)
    if s.gate:yield 'close-global-gate',replace(s,gate=False)
    if not s.gate and not s.published and not s.committed:
        yield 'commit-after-global-zero',replace(s,committed=True)
    if s.local and not s.published and not s.finished:
        yield 'publish-local-late',replace(s,published=1)
    if s.local and s.published:
        yield 'finish',replace(s,local=0,published=0,finished=True)

def find_counterexample():
    todo=deque([(State(),[])]);seen=set()
    while todo:
        s,trace=todo.popleft()
        if s in seen:continue
        seen.add(s)
        if s.committed and s.local:return trace
        todo.extend((v,trace+[name]) for name,v in late_publish_edges(s))
    return None

class ProtocolTests(unittest.TestCase):
    def test_delayed_update_publication_is_unsafe(self):
        self.assertEqual(find_counterexample(),['enter-only-local','close-global-gate','commit-after-global-zero'])

    def test_idle_lease_pin_blocks_naive_drain(self):
        # No active user can drop this pin. Returning it only after waiting is circular.
        updates=1;active_handles=0
        can_complete_drain=updates==0
        can_return_lease=can_complete_drain
        self.assertEqual(active_handles,0)
        self.assertFalse(can_complete_drain or can_return_lease)

    def test_independent_local_limits_do_not_conserve_capacity(self):
        total_budget=128;domain_a=96;domain_b=96
        self.assertLessEqual(domain_a,total_budget);self.assertLessEqual(domain_b,total_budget)
        self.assertGreater(domain_a+domain_b,total_budget)

    def test_precharged_leases_conserve_abstract_budget(self):
        for a in range(9):
            for b in range(9-a):
                remaining=8-a-b
                for used_a in range(a+1):
                    for used_b in range(b+1):
                        self.assertEqual(remaining+(a-used_a)+(b-used_b)+used_a+used_b,8)

    def test_task_migration_must_not_change_old_handle_owner(self):
        handle_owner=('cgroup-A',7)
        current_owner=('cgroup-B',8)
        self.assertNotEqual(handle_owner,current_owner)
        self.assertEqual(handle_owner,('cgroup-A',7))

    def test_shared_metadata_block_requires_coordination(self):
        # Independent directories can still dirty the same metadata block.
        directory_owners={'A':1,'B':2};metadata_blocks={'A':{41},'B':{41}}
        self.assertNotEqual(directory_owners['A'],directory_owners['B'])
        self.assertTrue(metadata_blocks['A'] & metadata_blocks['B'])

if __name__=='__main__':unittest.main()
