# SPDX-License-Identifier: GPL-2.0
import copy
import os
from pathlib import Path
import tempfile
import unittest
from budget import GIB,MIB,host_gate,parse_pool_status,pool_gate,validate_config
from identity import token,thin_id,regular
from manifest import Store
from template import validate_spec
from timing import validate_times


def config():
    return dict(data_bytes=24*GIB,metadata_bytes=128*MIB,chunk_sectors=128,max_branches=32,max_pending=4,root_floor=6*GIB)


class Tests(unittest.TestCase):
    def test_identifiers(self):
        for value in ('../a','/dev/sda','a'*31,'A'*32,'x'*32,1):
            with self.assertRaises(ValueError):token(value)
        self.assertEqual(token('a'*32),'a'*32)
        for value in (-1,2**24,True,'1'):
            with self.assertRaises(ValueError):thin_id(value)

    def test_config(self):
        self.assertEqual(validate_config(config()),config())
        for key,value in [('root_floor',5*GIB),('metadata_bytes',MIB),('chunk_sectors',129),('max_branches',100)]:
            c=config();c[key]=value
            with self.assertRaises(ValueError):validate_config(c)

    def test_capacity(self):
        with self.assertRaises(RuntimeError):host_gate(10*GIB,config(),True)
        host_gate(40*GIB,config(),True)
        s=parse_pool_status('0 50331648 thin-pool 0 10/1000 100/393216 - rw no_discard_passdown error_if_no_space - 64')
        pool_gate(s,GIB,GIB,config(),1)
        with self.assertRaises(RuntimeError):pool_gate(s,20*GIB,GIB,config(),1)
        s['metadata_used']=900
        with self.assertRaises(RuntimeError):pool_gate(s,GIB,GIB,config(),1)

    def test_unhealthy_status(self):
        for s in ('0 1 thin-pool Fail','0 1 thin-pool 0 1/2 1/2 - ro no_discard_passdown error_if_no_space -',
                  '0 1 thin-pool 0 1/2 1/2 - rw no_discard_passdown error_if_no_space needs_check'):
            with self.assertRaises(RuntimeError):parse_pool_status(s)

    def test_exclusive_store(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve()/'owned'
            s=Store(root,True,'test')
            try:
                with self.assertRaises(BlockingIOError):Store(root)
                row=s.intent('create_snap','a'*32)
                with self.assertRaises(RuntimeError):s.intent('delete','a'*32)
                s.commit(row,{'observed':True})
                self.assertIsNone(s.data['pending'])
            finally:s.close()
            s=Store(root)
            try:self.assertEqual(s.data['operations'][0]['outcome'],'VERIFIED')
            finally:s.close()

    def test_intent_survives_crash(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve()/'owned';s=Store(root,True,'test')
            row=s.intent('create_snap','b'*32);s.close()
            s=Store(root)
            try:
                self.assertEqual(s.data['pending'],row['token'])
                with self.assertRaises(RuntimeError):s.intent('create_snap','b'*32)
            finally:s.close()

    def test_replaced_directory_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve()/'owned';s=Store(root,True,'test')
            try:
                root.rename(Path(d).resolve()/'old');root.mkdir(mode=0o700)
                with self.assertRaises(RuntimeError):s.save()
            finally:s.close()

    def test_symlink_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'owned';root.mkdir(mode=0o700)
            link=Path(d)/'link';link.symlink_to(root)
            with self.assertRaises(RuntimeError):Store(link)

    def test_backing_identity(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'file';p.touch()
            self.assertEqual(regular(p)['bytes'],0)
            os.link(p,Path(d)/'alias')
            with self.assertRaises(RuntimeError):regular(p)

    def test_spec(self):
        validate_spec(dict(bytes=768*MIB,inodes=32768,journal_mib=16))
        with self.assertRaises(ValueError):validate_spec(dict(bytes=1,inodes=1,journal_mib=1))

    def test_completion_ack(self):
        t=dict(request=1,ready=2,business_start=3,business_end=10,completion_ack=11,cost_end=12,detached=13,mapping_reclaimed=14)
        self.assertEqual(validate_times(t)['business_s'],7e-9)
        for field,value in [('completion_ack',9),('cost_end',10),('mapping_reclaimed',12)]:
            q=copy.deepcopy(t);q[field]=value
            with self.assertRaises(ValueError):validate_times(q)


if __name__=='__main__':unittest.main()
