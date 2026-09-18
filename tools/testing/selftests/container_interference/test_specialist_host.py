# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import unittest
from specialist_vm_host import scratch_path


class SpecialistHostTests(unittest.TestCase):
    def test_exact_experiment_roots(self):
        self.assertTrue(scratch_path(Path('/dev/shm/cis-x-20260918/a/source')))
        self.assertTrue(scratch_path(Path('/dev/shm/cis-x-20260919/a/image.cpio')))
        for path in ('/dev/shm/cis-x-202609190/a', '/tmp/cis-x-20260919/a',
                     '/dev/shm/other/a', '/dev/shm/cis-x-20260920/a'):
            self.assertFalse(scratch_path(Path(path)))
