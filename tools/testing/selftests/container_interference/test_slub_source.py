# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT/'tools/container_interference'))
from collector_manifest import contract
from source_switches import expected_fields


class SlubSource(unittest.TestCase):
    def test_source_off_and_independent_gate(self):
        source = (ROOT/'kernel/locking/cis_observe.c').read_text()
        self.assertIn('trace_cis_slublock_state(object, kind, phase', source)
        self.assertIn('bitmap_zero(cis_waited[2]', source)
        self.assertIn('strcmp(name, alloc_cache)', source)
        fields = expected_fields('8', 'slub')
        self.assertEqual([k for k, v in fields.items() if v == '1'], ['slub'])
        self.assertEqual(expected_fields('8', None)['slub'], '0')
        with self.assertRaises(ValueError): expected_fields('7', 'slub')

    def test_all_native_node_operations_use_adapter(self):
        source = (ROOT/'mm/slub.c').read_text()
        # Raw lock operations are confined to four macros; initialization stays native.
        self.assertEqual(source.count('spin_lock_irqsave(&(n)->list_lock'), 1)
        self.assertEqual(source.count('spin_unlock_irqrestore(&(n)->list_lock'), 1)
        self.assertEqual(source.count('spin_lock_irq(&(n)->list_lock'), 1)
        self.assertEqual(source.count('spin_unlock_irq(&(n)->list_lock'), 1)
        self.assertEqual(source.count('spin_lock_irqsave(&n->list_lock'), 1)  # test-only oracle
        self.assertEqual(source.count('spin_unlock_irqrestore(&n->list_lock'), 1)
        self.assertIn('hold_us > 5000', source)
        self.assertIn('#ifdef CONFIG_CIS_SLUB_TEST', source)
        self.assertEqual(source.count('slub_node_event(s, n, CIS_RESET)'), 2)
        self.assertIn('slub_node_event(kmem_cache_node, n, CIS_RESET)', source)
        self.assertIn('slub_node_event(s, n, CIS_RETIRE)', source)

    def test_bound_profile_and_no_allocator_program(self):
        c = contract('slub')
        self.assertEqual(c['profile'], 12)
        self.assertEqual(c['programs'], ['owner_state', 'owner_switch'])
        self.assertNotIn('alloc_live', c['maps'])
        code = (ROOT/'tools/container_interference/bpf/cis.bpf.c').read_text()
        self.assertIn('SEC("raw_tp/cis_slublock_state")', code)
        self.assertIn('CIS_PROFILE == 12 ? key.kind != 4', code)

    def test_interrupt_boundary_does_not_name_current_or_reset_prefix(self):
        source=(ROOT/'kernel/locking/cis_observe.c').read_text()
        begin=source.index('void __cis_slub_event('); end=source.index('EXPORT_SYMBOL_GPL(__cis_slub_event)',begin)
        body=source[begin:end]
        self.assertIn('if (in_nmi())',body)
        self.assertIn('if (in_hardirq() || in_serving_softirq())',body)
        self.assertIn('phase = CIS_ESCAPE',body)
        bpf=(ROOT/'tools/container_interference/bpf/cis.bpf.c').read_text()
        self.assertIn('if(!(key.kind==4 && phase==7)) identity(task,&actor)',bpf)
        self.assertIn('(phase==7 && key.kind!=4)',bpf)
        self.assertIn('e.base.tid=(key.kind==4 && phase==7)?0:tid',bpf)


if __name__ == '__main__': unittest.main()
