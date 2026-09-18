# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import unittest


class AllocatorSource(unittest.TestCase):
    def test_filter_precedes_recursion_and_interrupt_exclusion(self):
        path=Path(__file__).resolve().parents[4]/'kernel/locking/cis_observe.c'
        if not path.exists(): self.skipTest('kernel file unavailable in this sparse checkout')
        text=path.read_text().split('void __cis_alloc_start(',1)[1].split('\n#endif',1)[0]
        self.assertLess(text.index('strcmp(name, alloc_cache)'),text.index('this_cpu_read(cis_in_trace)'))
        irq=text.split('if (in_interrupt())',1)[1].split('\n\t}',1)[0]
        self.assertIn('cis_alloc_irq_filtered',irq)
        self.assertNotIn('cis_skipped',irq)

    def test_source_steps_use_explicit_context_not_current_owner(self):
        path=Path(__file__).resolve().parents[4]/'mm/slub.c'
        if not path.exists(): self.skipTest('SLUB file unavailable in this sparse checkout')
        text=path.read_text()
        self.assertIn('CIS_CA_NODE_WAIT',text)
        self.assertIn('CIS_CA_NODE_HELD',text)
        self.assertIn('CIS_CA_BULK_ROLLBACK',text)
        self.assertNotIn('current->cis',text)
