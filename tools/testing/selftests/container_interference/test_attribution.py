#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
import importlib.util
import pathlib
import unittest

source = pathlib.Path(__file__).resolve().parents[3] / 'container_interference/attribution.py'
spec = importlib.util.spec_from_file_location('attribution', source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class AttributionTest(unittest.TestCase):
    def test_lock_wait_does_not_create_holder(self):
        record = {'kind': 'E1', 'id': 1, 'generation': 2,
                  'detail': 'type=3 object=0x123 duration_ns=42 owner=unknown'}
        result = module.classify(record)
        self.assertEqual(result['level'], 'E1')
        self.assertEqual(result['owner'], 'unknown')
        self.assertFalse(result['causal'])
        self.assertFalse(result['duration_is_pure_spin'])
        self.assertIn('unresolved_reuse', result['object_lifetime'])

    def test_incomplete_is_not_zero(self):
        result = module.classify({'kind': 'incomplete', 'detail': 'begin_ns=123'})
        self.assertIsNone(result['duration_ns'])

    def test_no_fake_total(self):
        result = module.analyze(['{"kind":"E1","detail":"type=2 duration_ns=100"}',
                                 '{"kind":"E1","detail":"type=3 duration_ns=100"}'])
        self.assertIsNone(result['additive_total'])

    def test_invalid_record_is_reported(self):
        result = module.analyze(['broken'])
        self.assertEqual(len(result['parse_errors']), 1)

    def test_overlap_proves_only_cowaiters(self):
        records = ['{"kind":"E1","id":1,"generation":1,"detail":"type=3 flags=32 object=0x1 sample_time_ns=100 duration_ns=200"}',
                   '{"kind":"E1","id":2,"generation":2,"detail":"type=3 flags=33 object=0x1 sample_time_ns=200 duration_ns=200"}']
        result = module.analyze(records)
        self.assertEqual(len(result['relations']), 1)
        self.assertEqual(result['relations'][0]['relation'], 'cross_container_cowaiters')
        self.assertFalse(result['relations'][0]['causal'])
        self.assertEqual(result['relations'][0]['owner'], 'unknown')

    def test_reused_address_is_not_merged(self):
        result = module.analyze(['{"kind":"E1","id":1,"generation":1,"detail":"type=3 flags=32 object=0x1 sample_time_ns=100 duration_ns=10"}',
                                 '{"kind":"E1","id":2,"generation":2,"detail":"type=3 flags=32 object=0x1 sample_time_ns=200 duration_ns=10"}'])
        self.assertEqual(result['relations'], [])

    def test_same_function_different_object_not_merged(self):
        result = module.analyze(['{"kind":"E1","id":1,"generation":1,"detail":"type=3 flags=32 object=0x1 sample_time_ns=100 duration_ns=500"}',
                                 '{"kind":"E1","id":2,"generation":2,"detail":"type=3 flags=32 object=0x2 sample_time_ns=100 duration_ns=500"}'])
        self.assertEqual(result['relations'], [])


if __name__ == '__main__':
    unittest.main()
