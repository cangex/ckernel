# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import re
import unittest

from collector_manifest import COLLECTORS


class DiagnosticLinks(unittest.TestCase):
    def test_pairs_cover_all_specialist_programs_without_mask_drift(self):
        source=(Path(__file__).resolve().parents[3]/'container_interference/capture.c').read_text()
        body=source.split('static int configure_links(',1)[1].split('_Static_assert',1)[0]
        pairs=re.findall(r'\{"([a-z_]+)",(\d+)\}',body)
        links={name:int(mask) for name,mask in pairs}
        self.assertEqual(len(pairs),len(links))
        self.assertEqual(len(links),int(re.search(r'#define CIS_DIAGNOSTIC_LINKS (\d+)',source)[1]))
        for key,mask in [('sched',1),('sync',2),('reclaim',4),
                         ('owner',16),('fd',16),('counter',32),('allocator',64),
                         ('net',128),('block',256),('rwsem',512)]:
            for name in COLLECTORS[key]['programs']:
                self.assertEqual(links[name],mask,(key,name))
        self.assertEqual({name for name,mask in links.items() if mask==8},
                         {'work_queue','work_start','work_end','work_cancel_begin','work_cancel_end'})


if __name__=='__main__': unittest.main()
