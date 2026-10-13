import os
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from fs_domain_plan import COUNTS,layout,placement,required_free,GIB,matrix_rotation
from fs_domain_lifecycle import Manager,record_identity,check_identity,loop_identity

class PlanTests(unittest.TestCase):
    def test_conservation(self):
        for n in COUNTS:
            p=layout(n)
            self.assertEqual(sum(x['bytes'] for x in p),18*GIB)
            self.assertEqual(sum(x['journal_mib'] for x in p),384)
            self.assertEqual(sum(x['inodes'] for x in p),786432)
    def test_balanced_groups(self):
        for b in range(5):
            for n in COUNTS:
                groups=[placement(s,n,matrix_rotation(b)) for s in range(24)]
                self.assertEqual([groups.count(g) for g in range(n)],[24//n]*n)
                if n<=4:
                    for node in (0,1):
                        local=groups[node*12:(node+1)*12]
                        self.assertEqual([local.count(g) for g in range(n)],[12//n]*n)
    def test_invalid(self):
        for n in (0,3,23,25):
            with self.assertRaises(ValueError):layout(n)
        with self.assertRaises(ValueError):placement(24,24)
    def test_capacity(self):
        self.assertGreater(required_free(18*GIB),27*GIB)
    def test_exclusive_creation(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d).resolve()/'owned';m=Manager(p,True);m.close()
            with self.assertRaises(FileExistsError):Manager(p,True)
    def test_lock(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d).resolve()/'owned';m=Manager(p,True)
            try:
                with self.assertRaises(BlockingIOError):Manager(p)
            finally:m.close()
    def test_symlink_root(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'real').mkdir();(p/'link').symlink_to(p/'real',target_is_directory=True)
            with self.assertRaises(RuntimeError):Manager(p/'link')
    def test_image_replacement(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'image';p.write_bytes(b'x');identity=record_identity(p);p.write_bytes(b'xx')
            with self.assertRaises(RuntimeError):check_identity(p,identity)
    def test_hardlink(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'image';p.write_bytes(b'x');os.link(p,Path(d)/'alias')
            with self.assertRaises(RuntimeError):record_identity(p)
    def test_foreign_loop(self):
        with patch('fs_domain_lifecycle.run',return_value='{"loopdevices":[{"name":"/dev/loop5","back-file":"/other.img"}]}'):
            with self.assertRaises(RuntimeError):loop_identity('/dev/loop5',Path('/owned.img'))
    def test_physical_device_refused(self):
        with self.assertRaises(RuntimeError):loop_identity('/dev/sdb',Path('/owned.img'))
    def test_foreign_container(self):
        with tempfile.TemporaryDirectory() as d:
            m=Manager(Path(d).resolve()/'owned',True)
            try:
                with patch('fs_domain_lifecycle.run',side_effect=['id','[{"Id":"id","Mounts":[{"Source":"/test/mnt/slot-0"}]}]']):
                    with self.assertRaises(RuntimeError):m.assert_unused(dict(mount='/test/mnt'))
            finally:m.close()

if __name__=='__main__':unittest.main()
