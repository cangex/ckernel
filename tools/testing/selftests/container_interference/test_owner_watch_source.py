# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import unittest


class OwnerWatchSource(unittest.TestCase):
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
