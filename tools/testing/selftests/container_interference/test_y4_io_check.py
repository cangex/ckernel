# SPDX-License-Identifier: GPL-2.0
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'container_interference'))
from y4_io_check import case_order, check_case


class IOTruthTests(unittest.TestCase):
    def test_frozen_nonces(self):
        rows = case_order()
        self.assertEqual(len(rows), 24)
        self.assertEqual(len({r['label'] for r in rows}), 24)
        self.assertTrue(all(r['label'].isalnum() and len(r['label']) <= 64 for r in rows))
        self.assertEqual([r['enabled'] for r in rows[8:10]], [True, False])

    def test_private_files_required(self):
        logs = ['CIS_IO_DONE role=%d begin_ns=2 written_ns=3 synced_ns=4 end_ns=5 '
                'directory_inode=12 inode=13 major=253 minor=0 bytes=8388608 '
                'sync_each=1 verified=1 errors=0' % i for i in range(2)]
        r = check_case('shared_sync', dict(start_ns=1, end_ns=10), logs)
        self.assertIn('objects_not_private', r['errors'])
        logs[1] = logs[1].replace('directory_inode=12 inode=13', 'directory_inode=14 inode=15')
        self.assertEqual(check_case('shared_sync', dict(start_ns=1, end_ns=10), logs)['status'], 'PASS')


if __name__ == '__main__': unittest.main()
