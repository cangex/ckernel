# SPDX-License-Identifier: GPL-2.0
import unittest
from go_adapter import geometry


class GeometryTests(unittest.TestCase):
    def test_aggregate_match(self):
        for arm in 'SGFB':
            specs=geometry(arm,24)
            self.assertEqual(sum(x['bytes'] for x in specs),18*1024**3)
            self.assertEqual(sum(x['inodes'] for x in specs),787968)
            self.assertEqual(sum(x['journal_mib'] for x in specs),384)

    def test_target_same_geometry(self):
        for arm in 'SGFB':self.assertEqual(geometry(arm,1)[0],geometry(arm,24)[0])

    def test_no_expansion(self):
        for arm,n in [('X',24),('B',48)]:
            with self.assertRaises(ValueError):geometry(arm,n)
