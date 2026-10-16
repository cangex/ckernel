# SPDX-License-Identifier: GPL-2.0
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fs_domain_lifecycle import Manager
from fs_groupctl import create, specs


class DeliveryTests(unittest.TestCase):
    def test_go_geometry(self):
        volumes = specs(4, 9, 393984, 192)
        self.assertEqual(sum(v['bytes'] for v in volumes), 36 * 1024**3)
        self.assertEqual(sum(v['journal_mib'] for v in volumes), 768)

    def test_geometry_rejects(self):
        for args in ((0, 9, 393984, 192), (49, 9, 393984, 192),
                     (4, 0, 393984, 192), (4, 9, 0, 192), (4, 1, 1024, 512)):
            with self.assertRaises(ValueError):
                specs(*args)

    def test_bad_slots_do_not_create(self):
        with patch('fs_groupctl.Manager') as manager:
            for slots in (0, 49, True):
                with self.assertRaises(ValueError):
                    create('/unused', slots, specs(4, 9, 393984, 192))
            manager.assert_not_called()

    def test_48_slots_modulo_four(self):
        with patch('fs_groupctl.Manager') as constructor:
            m = constructor.return_value
            m.state = {'volumes': []}
            create('/unused', 48, specs(4, 9, 393984, 192))
            self.assertEqual([c.args for c in m.private_directory.call_args_list],
                             [(i, i % 4) for i in range(48)])
            m.close.assert_called_once()

    def test_failure_keeps_evidence(self):
        with patch('fs_groupctl.Manager') as constructor:
            m = constructor.return_value
            m.create_volumes.side_effect = RuntimeError('format failed')
            with self.assertRaises(RuntimeError):
                create('/unused', 12, specs(4, 9, 393984, 192))
            m.close.assert_called_once()
            m.teardown.assert_not_called()

    def test_manifest_escape_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / 'owned'
            m = Manager(root, True)
            m.state['volumes'] = [{'image': '/dev/sdb', 'mount': '/unowned'}]
            m.persist()
            m.close()
            with self.assertRaises(RuntimeError):
                Manager(root)

    def test_symlink_manifest_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / 'owned'
            m = Manager(root, True)
            m.close()
            (root / 'manifest.json').rename(root / 'original.json')
            (root / 'manifest.json').symlink_to(root / 'original.json')
            with self.assertRaises(RuntimeError):
                Manager(root)

    def test_permissive_state_root_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / 'owned'
            m = Manager(root, True)
            m.close()
            root.chmod(0o755)
            with self.assertRaises(RuntimeError):
                Manager(root)

    def test_48th_directory_and_duplicate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / 'owned'
            m = Manager(root, True)
            mount = root / 'mount-0'
            mount.mkdir()
            m.state.update(state='ACTIVE', volumes=[dict(mount=str(mount), uuid='test')])
            try:
                with patch.object(m, 'verify_volume'):
                    self.assertEqual(m.private_directory(47, 0), mount / 'slot-47')
                    with self.assertRaises(RuntimeError):
                        m.private_directory(47, 0)
                    with self.assertRaises(RuntimeError):
                        m.private_directory(48, 0)
            finally:
                m.close()


if __name__ == '__main__':
    unittest.main()
