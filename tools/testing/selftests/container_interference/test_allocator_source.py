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

    def test_release_precedes_reuse_and_gaps_invalidate_identity(self):
        root=Path(__file__).resolve().parents[4]
        text=(root/'mm/slub.c').read_text().split('static __fastpath_inline void slab_free(',1)[1]
        self.assertLess(text.index('cis_alloc_release('),text.index('memcg_slab_free_hook('))
        text=(root/'kernel/locking/cis_observe.c').read_text().split('void __cis_alloc_release(',1)[1].split('void __cis_alloc_step(',1)[0]
        self.assertIn('count > CIS_CA_STEPS',text)
        self.assertIn('this_cpu_inc(cis_skipped)',text)
        self.assertNotIn('current->',text)

    def test_release_guard_separates_preempting_context_not_owner(self):
        root=Path(__file__).resolve().parents[4]
        text=(root/'kernel/locking/cis_observe.c').read_text().split('void __cis_alloc_release(',1)[1].split('void __cis_alloc_step(',1)[0]
        self.assertIn('guard->active[context]',text)
        self.assertIn('(!context && this_cpu_read(cis_in_trace))',text)
        self.assertIn('cis_alloc_free_nested',text)
        self.assertIn('cis_alloc_free_nmi',text)
        self.assertIn('cis_alloc_free_irq',text)
        self.assertNotIn('local_irq_disable',text)

    def test_release_masks_only_one_callback_and_measures_cost(self):
        root=Path(__file__).resolve().parents[4]
        text=(root/'kernel/locking/cis_observe.c').read_text().split('void __cis_alloc_release(',1)[1].split('void __cis_alloc_step(',1)[0]
        loop=text.index('for (i = 0;')
        self.assertGreater(text.index('guard->active[context] = true'),loop)
        self.assertGreater(text.index('local_irq_save('),loop)
        self.assertLess(text.index('local_irq_save('),text.index('trace_cis_alloc_release('))
        self.assertLess(text.index('trace_cis_alloc_release('),text.index('guard->active[context] = false'))
        self.assertLess(text.index('guard->active[context] = false'),text.index('local_irq_restore('))
        self.assertIn('cis_alloc_free_callback_max_ns',text)
