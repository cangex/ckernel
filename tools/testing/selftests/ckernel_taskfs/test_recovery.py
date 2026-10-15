# SPDX-License-Identifier: GPL-2.0
import unittest
from unittest.mock import Mock,patch
from recovery import reconcile_drained_namespace
from dm_backend import Backend


class RecoveryTests(unittest.TestCase):
    def fixture(self):
        obj=dict(id='branch',active=True,mounted=True,state='ATTACHED',dev='253:3',name='owned')
        store=Mock();store.data=dict(branches={'branch':obj},pending=None,boot='same');store.boot.return_value='same'
        backend=Mock(spec=Backend);backend.verify_mapping.return_value=dict(open=0)
        backend.fs_header.return_value={'Filesystem state':'clean'}
        backend.operation.side_effect=lambda action,item,effect,observe:(effect(),observe())
        return obj,store,backend

    def test_reference_free_seals_result_without_replay(self):
        obj,s,b=self.fixture()
        with patch('recovery.inventory',return_value=[]):result=reconcile_drained_namespace(s,b,'branch')
        self.assertTrue(result['retained_result']);self.assertEqual(obj['state'],'SEALED')
        b.remove_mapping.assert_called_once_with(obj)
        self.assertEqual(b.run.call_args.args[0][0],'e2fsck')

    def test_ambiguous_or_changed_boot_refused(self):
        for key,value in [('pending','token'),('boot','other')]:
            _,s,b=self.fixture();s.data[key]=value
            with self.assertRaises(RuntimeError):reconcile_drained_namespace(s,b,'branch')
            b.remove_mapping.assert_not_called()

    def test_mount_open_or_fd_refused(self):
        for mode in ('mount','open','fd'):
            obj,s,b=self.fixture()
            if mode=='open':b.verify_mapping.return_value=dict(open=1)
            if mode=='fd':b.assert_no_references.side_effect=RuntimeError('FD reference')
            with patch('recovery.inventory',return_value=[1] if mode=='mount' else []):
                with self.assertRaises(RuntimeError):reconcile_drained_namespace(s,b,'branch')
            self.assertEqual(obj['state'],'ATTACHED');b.remove_mapping.assert_not_called()

    def test_fsck_failure_preserves_mapping(self):
        obj,s,b=self.fixture();b.run.side_effect=RuntimeError('fsck failure')
        with patch('recovery.inventory',return_value=[]):
            with self.assertRaises(RuntimeError):reconcile_drained_namespace(s,b,'branch')
        b.remove_mapping.assert_not_called();self.assertTrue(obj['mounted'])
