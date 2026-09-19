# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import tempfile
import unittest
from specialist_vm_host import image_path, scratch_path


class SpecialistHostTests(unittest.TestCase):
    def test_exact_experiment_roots(self):
        self.assertTrue(scratch_path(Path('/dev/shm/cis-x-20260918/a/source')))
        self.assertTrue(scratch_path(Path('/dev/shm/cis-x-20260919/a/image.cpio')))
        for path in ('/dev/shm/cis-x-202609190/a', '/tmp/cis-x-20260919/a',
                     '/dev/shm/other/a', '/dev/shm/cis-x-20260920/a'):
            self.assertFalse(scratch_path(Path(path)))

    def test_image_roots_resolve_before_check(self):
        base = Path('/root/cis-20260916-232524')
        for path in (base/'evidence/build/Image',
                     Path('/dev/shm/cis-x-20260919/build/Image'),
                     Path('/dev/shm/cis-x-20260918/build/Image')):
            self.assertTrue(image_path(path, base))
        for path in ('/boot/Image', '/dev/shm/cis-x-202609190/Image',
                     '/dev/shm/cis-x-20260920/Image',
                     '/dev/shm/cis-x-20260919/../other/Image',
                     '/root/cis-20260916-232524/../other/Image'):
            self.assertFalse(image_path(Path(path), base))

    def test_image_symlink_cannot_escape_base(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root/'dedicated'
            base.mkdir()
            (base/'outside').symlink_to(root/'outside')
            self.assertFalse(image_path(base/'outside'/'Image', base))
            self.assertTrue(image_path(base/'Image', base))
