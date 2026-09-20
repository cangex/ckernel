# SPDX-License-Identifier: GPL-2.0
import unittest
from collector_manifest import COMMON_MAPS, LEGACY_COUNTER, contract, validate_inventory, validate_record_inventory
from periodic_plan import digest
import test_collector_manifest


class CounterLegacy(unittest.TestCase):
    def test_history_requires_pinned_old_contract_live_does_not_accept_it(self):
        maps=COMMON_MAPS+['targets','stacks','pending']
        old=contract('counter'); old.update(LEGACY_COUNTER); old['maps']=maps
        inventory=test_collector_manifest.CollectorContract().inventory('counter')
        inventory.update(map_names=maps,maps=list(range(1,len(maps)+1)))
        record=dict(collector='counter',inventory=inventory,collector_contract_sha256=digest(old))
        self.assertEqual(validate_record_inventory(record),digest(old))
        with self.assertRaises(ValueError): validate_inventory('counter',inventory)
        with self.assertRaises(ValueError): validate_record_inventory(dict(record,collector_contract_sha256='0'*64))
        with self.assertRaises(ValueError): validate_record_inventory(dict(record,selected_objects=[8]))
