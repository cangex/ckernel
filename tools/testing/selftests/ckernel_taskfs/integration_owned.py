#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Opt-in normal-operation test on a NEW private regular-file pool only.

No no-space, power-loss, kernel crash or metadata corruption injection here.
"""
import argparse
import json
import os
from pathlib import Path
import time
from budget import GIB,MIB
from dm_backend import Backend
from identity import new_token
from lifecycle import Lifecycle
from manifest import Store


def main():
    p=argparse.ArgumentParser();p.add_argument('root');p.add_argument('--execute-owned-files',action='store_true')
    a=p.parse_args()
    if not a.execute_owned_files:p.error('explicit execution option required')
    s=Store(a.root,True,'normal-integration');b=Backend(s);life=Lifecycle(s,b)
    outcome=dict(status='FAIL',scope='normal native dm-thin/ext4 integration, not crash/ENOSPC/Go acceptance',checks=[])
    try:
        if b.run(['docker','ps','-q']):raise RuntimeError('active work; integration refused')
        before=b.run(['dmsetup','info','-c','--noheadings','-o','name,uuid']).splitlines()
        b.prepare_pool(dict(data_bytes=4*GIB,metadata_bytes=64*MIB,chunk_sectors=128,
            max_branches=4,max_pending=2,root_floor=6*GIB))
        spec=dict(bytes=512*MIB,inodes=32768,journal_mib=16)
        template=life.prepare_template(spec,new_token())
        left=life.create(spec,new_token(),template['id']);right=life.create(spec,new_token(),template['id'])
        fresh=life.create(spec,new_token())
        assert len({o['dev'] for o in (left,right,fresh)})==3
        assert len({tuple(o['journal_interfaces']) for o in (left,right,fresh)})==3
        outcome['checks'].append('distinct live ext4 devices and journal interfaces')
        for index,obj in enumerate((left,right,fresh)):
            payload=Path(obj['payload']);file=payload/'same-name'
            with file.open('wb') as f:f.write(str(index).encode());f.flush();os.fsync(f.fileno())
            os.setxattr(file,'user.cktaskfs',str(index).encode())
            link=payload/'link';os.link(file,link)
            assert link.stat().st_ino==file.stat().st_ino
            link.rename(payload/'renamed');(payload/'renamed').unlink()
        assert [(Path(o['payload'])/'same-name').read_text() for o in (left,right,fresh)]==['0','1','2']
        outcome['checks'].append('same-path isolation; domain-local hardlink/rename/unlink; fsynced sentinel and xattr')
        with (Path(left['payload'])/'same-name').open('rb'):
            try:life.destroy(left['id'])
            except RuntimeError as exc:
                if 'reference' not in str(exc):raise
            else:raise AssertionError('open FD destruction accepted')
        assert left['state']=='READY'
        outcome['checks'].append('open FD refusal before mutation')
        life.verify_template(template['id']);outcome['checks'].append('template payload unchanged after CoW writes')
        life.seal(left['id'])
        b.activate(left,readonly=True);b.mount(left,readonly=True);left['mounted']=True;s.save()
        assert (Path(left['payload'])/'same-name').read_text()=='0'
        b.unmount(left);b.remove_mapping(left)
        outcome['checks'].append('sealed result survives normal sync/unmount/read-only reopen')
        for obj in (left,right,fresh):life.destroy(obj['id'])
        b.destroy_pool()
        after=b.run(['dmsetup','info','-c','--noheadings','-o','name,uuid']).splitlines()
        assert sorted(before)==sorted(after)
        outcome['checks'].append('all own mappings/backing removed; original DM inventory unchanged')
        outcome['status']='PASS'
    except BaseException as exc:
        outcome['error']=repr(exc)
        raise
    finally:
        outcome['end_ns']=time.monotonic_ns();s.data['integration_result']=outcome;s.save();s.close()
        print(json.dumps(outcome))


if __name__=='__main__':main()
