# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import unittest

from collector_manifest import contract, validate_record_inventory, validate_inventory
from joint_costs import rwsem_audit, rwsem_audit_delta
from periodic_plan import digest
from source_switches import expected_fields
import test_collector_manifest


class RwsemFilter(unittest.TestCase):
    def test_native_and_legacy_receipts_are_distinct(self):
        current=contract('rwsem'); old=contract('rwsem',legacy_rwsem=True)
        self.assertNotEqual(digest(current),digest(old))
        inventory=test_collector_manifest.CollectorContract().inventory('rwsem')
        for value in (current,old):
            row=dict(collector='rwsem',inventory=inventory,collector_contract_sha256=digest(value))
            self.assertEqual(validate_record_inventory(row),digest(value))
        self.assertEqual(validate_inventory('rwsem',inventory),digest(current))

    def test_native_filter_is_an_independent_source_switch(self):
        self.assertEqual(expected_fields('10','rwsem')['rwsem_filter'],'1')
        for collector in (None,'owner','fd','slub','counter','net','block','allocator'):
            self.assertEqual(expected_fields('10',collector)['rwsem_filter'],'0')
        self.assertNotIn('rwsem_filter',expected_fields('9','rwsem'))

    def test_native_entry_denominator_does_not_disappear(self):
        a='version=1\ncpu=0 entries=100 filtered=90\ncpu=1 entries=20 filtered=10\n'
        b='version=1\ncpu=0 entries=1100 filtered=1080\ncpu=1 entries=40 filtered=25\n'
        row=rwsem_audit_delta(a,b)
        self.assertEqual((row['entries'],row['filtered'],row['selected']),(1020,1005,15))
        with self.assertRaisesRegex(ValueError,'regression'): rwsem_audit_delta(b,a)
        with self.assertRaisesRegex(ValueError,'topology'): rwsem_audit_delta(a,'version=1\ncpu=0 entries=100 filtered=90\n')
        for text in ('version=2\ncpu=0 entries=1 filtered=1\n',
                     'version=1\ncpu=0 entries=1 filtered=1\ncpu=0 entries=2 filtered=1\n',
                     'version=1\ncpu=0 entries=-1 filtered=1\n'):
            with self.assertRaises(ValueError): rwsem_audit(text)

    def test_selection_precedes_bpf_and_is_lease_owned(self):
        root=Path(__file__).resolve().parents[4]
        c=(root/'kernel/locking/cis_observe.c').read_text().split('void __cis_rwsem_event',1)[1]
        self.assertLess(c.index('cis_rwsem_filter_allows'),c.index('trace_cis_rwsem_state'))
        f=(root/'kernel/locking/cis_rwsem_filter.c').read_text()
        fast=f.split('bool cis_rwsem_filter_allows',1)[1].split('int cis_rwsem_observe_register',1)[0]
        self.assertNotIn('mutex_lock',fast)
        self.assertIn('kfree_rcu(filter, rcu)',f)
        self.assertIn('ns_capable(&init_user_ns, CAP_SYS_ADMIN)',f)
        self.assertIn('lease || attached',f)


if __name__=='__main__': unittest.main()
