# SPDX-License-Identifier: GPL-2.0
import unittest
from mount_guard import mirrors, record


class MountGuardTests(unittest.TestCase):
    def rows(self):
        return [('host',record('394 1 253:3 / /owned rw shared:100 - ext4 /dev/dm-3 rw')),
                ('slave',record('401 2 253:3 / /owned rw master:100 - ext4 /dev/dm-3 rw'))]

    def test_normal_propagation(self):
        self.assertEqual(mirrors(self.rows(),'host',394,'253:3','/owned'),
                         {('host','394'),('slave','401')})

    def test_unrelated_group(self):
        rows=self.rows();rows[1][1]['tags']={'master:101'}
        with self.assertRaises(RuntimeError):mirrors(rows,'host',394,'253:3','/owned')

    def test_bind_or_moved_mount(self):
        for field,value in [('root','/subdir'),('target','/elsewhere')]:
            rows=self.rows();rows[1][1][field]=value
            with self.assertRaises(RuntimeError):mirrors(rows,'host',394,'253:3','/owned')

    def test_no_host_identity(self):
        with self.assertRaises(RuntimeError):mirrors(self.rows(),'host',999,'253:3','/owned')
