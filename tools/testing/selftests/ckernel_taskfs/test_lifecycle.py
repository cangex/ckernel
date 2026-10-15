# SPDX-License-Identifier: GPL-2.0
"""Control model tests, not block-device or filesystem correctness evidence."""
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from budget import GIB,MIB
from identity import new_token
from lifecycle import Lifecycle
from manifest import Store


class Fake:
    def __init__(self,s):self.s=s;self.busy=False
    def verify_pool(self):return dict(data_used=1,data_total=1000,metadata_used=1,metadata_total=1000)
    def verify_mapping(self,o):return dict(dev=o.get('dev','model-only'))
    def new_thin(self,o,origin=None):o['thin_created']=True
    def activate(self,o):o.update(active=True,name='fake-'+o['id'])
    def format(self,o):o['formatted']=True
    def mount(self,o):
        o['mount']=str(self.s.root/('mount-'+o['id']));Path(o['mount']).mkdir()
    def mount_identity(self,o):return {'model':True}
    def operation(self,action,o,effect,observe):
        row=self.s.intent(action,o['id'])
        try:effect();self.s.commit(row,observe())
        except BaseException as exc:self.s.failure(row,exc);raise
    def assert_no_references(self,o,allow_host_mount=False):
        if self.busy:raise RuntimeError('model busy')
    def unmount(self,o):o['mounted']=False
    def remove_mapping(self,o):o['active']=False
    def run(self,args):return ''
    def fs_header(self,o):return {'Filesystem state':'clean'}
    def delete_thin(self,o):o['reclaim']={'mapping_reclaimed_ns':time.monotonic_ns()}


class Tests(unittest.TestCase):
    def setUp(self):
        self.tree=patch('lifecycle.tree_digest',return_value=[{'control_model_only':True}])
        self.tree.start();self.addCleanup(self.tree.stop)
        self.tmp=tempfile.TemporaryDirectory()
        self.s=Store(Path(self.tmp.name).resolve()/'control',True,'model')
        self.s.data.update(state='ACTIVE',pool={'config':dict(data_bytes=24*GIB,metadata_bytes=128*MIB,
            max_branches=32,max_pending=4,root_floor=6*GIB,chunk_sectors=128)})
        self.b=Fake(self.s);self.l=Lifecycle(self.s,self.b)
        self.spec=dict(bytes=768*MIB,inodes=32768,journal_mib=16)
    def tearDown(self):self.s.close();self.tmp.cleanup()

    def test_no_writable_reuse(self):
        a=self.l.create(self.spec,new_token());self.l.destroy(a['id'])
        b=self.l.create(self.spec,new_token())
        self.assertNotEqual(a['id'],b['id']);self.assertGreater(b['thin_id'],a['thin_id'])
        self.assertEqual(a['state'],'DELETED');self.assertEqual(b['state'],'READY')

    def test_request_retry(self):
        request=new_token();a=self.l.create(self.spec,request)
        self.assertEqual(a['id'],self.l.create(self.spec,request)['id'])
        self.assertEqual(len(self.s.data['branches']),1)

    def test_deleted_request_not_recycled(self):
        request=new_token();a=self.l.create(self.spec,request);self.l.destroy(a['id'])
        with self.assertRaises(RuntimeError):self.l.create(self.spec,request)

    def test_request_conflict(self):
        request=new_token();self.l.create(self.spec,request)
        spec=dict(self.spec,bytes=1024*MIB)
        with self.assertRaises(RuntimeError):self.l.create(spec,request)

    def test_busy_rejects_without_destruction(self):
        a=self.l.create(self.spec,new_token());self.b.busy=True
        with self.assertRaises(RuntimeError):self.l.destroy(a['id'])
        self.assertEqual(a['state'],'READY');self.assertTrue(a['active'])

    def test_seal_preserves_result(self):
        a=self.l.create(self.spec,new_token());self.l.seal(a['id'])
        self.assertEqual(a['state'],'SEALED');self.assertFalse(a['active'])
        self.assertNotIn('reclaim',a)

    def test_unfinished_branch_blocks(self):
        a=self.l.allocate_record(self.spec,new_token(),'branch',None)
        with self.assertRaises(RuntimeError):self.l.create(self.spec,new_token())
        result=self.l.recover()
        self.assertEqual(result['status'],'RECOVERY_REQUIRED')
        self.assertIn(a['id'],result['incomplete'])

    def test_ambiguous_each_effect_not_replayed(self):
        for action in ('create_snap','activate','mount','attach','unmount','remove','delete'):
            row=self.s.intent(action,'c'*32)
            report=self.l.recover()
            self.assertEqual(report['status'],'RECOVERY_REQUIRED')
            self.assertFalse(report['automatic_mutation'])
            self.assertEqual(self.s.data['pending'],row['token'])
            # Only the model resolves its injected intent; production recovery cannot do this.
            self.s.commit(row,{'model_only':True})


if __name__=='__main__':unittest.main()
