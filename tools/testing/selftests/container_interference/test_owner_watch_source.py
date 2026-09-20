# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import unittest


class OwnerWatchSource(unittest.TestCase):
    def test_fd_prefix_is_bounded_and_all_gates_agree(self):
        source=Path(__file__).resolve().parents[3]/'container_interference'
        code=(source/'bpf/cis.bpf.c').read_text()
        self.assertIn('return kind==3 ? 128 : 64;',code)
        owner=code[code.index('int owner_state('):code.index('SEC("raw_tp/sched_switch")')]
        self.assertEqual(owner.count('w->events>owner_prefix_limit('),3)
        self.assertIn('if(seq==owner_prefix_limit(key.kind)) phase=11;',owner)
        self.assertIn('else if(seq>owner_prefix_limit(key.kind)) return 0;',owner)
        self.assertIn('__sync_fetch_and_add(&w->events,1)',owner)
        self.assertNotIn('w->events>64',owner)
        self.assertIn('__uint(max_entries,64); __type(key,struct cis_object_key)',code)

    def test_collision_requires_live_object_and_other_errors_are_rejected(self):
        source=Path(__file__).resolve().parents[3]/'container_interference'
        code=(source/'bpf/cis.bpf.c').read_text()
        self.assertIn('if(result && result!=-17)',code)
        self.assertIn('if(!live_watch(w,now)) {COUNT(s,owner_watch_failed);COUNT(s,rejected);return 0;}',code)
        self.assertIn('if(result==-17) COUNT(s,owner_watch_races);',code)
        self.assertNotIn('bpf_map_delete_elem(&holders,&key);\n\t\t\tw=',code)
        self.assertIn('h->epoch==w->epoch',code)
        self.assertIn('h->epoch!=w->epoch || ht->epoch!=w->epoch',code)
        capture=(source/'capture.c').read_text()
        for counter in ('watch_races','watch_failed','holder_failed','attempt_failed'):
            self.assertIn(counter+'=%llu',capture)


if __name__=='__main__': unittest.main()
