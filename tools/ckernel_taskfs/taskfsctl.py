#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Explicit lifecycle CLI. No arbitrary backing-device argument is accepted."""
import argparse
import json
from budget import GIB,MIB
from dm_backend import Backend
from lifecycle import Lifecycle
from manifest import Store


def main():
    p=argparse.ArgumentParser()
    p.add_argument('action',choices=('inspect','prepare-template','create','attach','running','status','seal','destroy','recover','gc'))
    p.add_argument('root')
    p.add_argument('--stamp')
    p.add_argument('--request-id')
    p.add_argument('--branch')
    p.add_argument('--container')
    p.add_argument('--template')
    p.add_argument('--initialize-owned-file-pool',action='store_true')
    p.add_argument('--destroy-owned-pool',action='store_true')
    p.add_argument('--data-gib',type=int,default=24)
    p.add_argument('--metadata-mib',type=int,default=128)
    p.add_argument('--chunk-sectors',type=int,default=128)
    p.add_argument('--logical-mib',type=int,default=768)
    p.add_argument('--inodes',type=int,default=32768)
    p.add_argument('--journal-mib',type=int,default=16)
    a=p.parse_args()
    if a.initialize_owned_file_pool and (a.action!='prepare-template' or not a.stamp):
        p.error('pool initialization only during prepare-template with stamp')
    if a.destroy_owned_pool and a.action!='gc':p.error('pool destruction only through explicit gc')
    if a.action in ('prepare-template','create') and not a.request_id:p.error('explicit request-id required')
    s=Store(a.root,create=a.initialize_owned_file_pool,stamp=a.stamp)
    try:
        if a.action=='inspect':result=s.data
        else:
            backend=Backend(s);life=Lifecycle(s,backend)
            if a.initialize_owned_file_pool:
                backend.prepare_pool(dict(data_bytes=a.data_gib*GIB,metadata_bytes=a.metadata_mib*MIB,
                    chunk_sectors=a.chunk_sectors,max_branches=32,max_pending=4,root_floor=6*GIB))
            spec=dict(bytes=a.logical_mib*MIB,inodes=a.inodes,journal_mib=a.journal_mib)
            if a.action=='prepare-template':result=life.prepare_template(spec,a.request_id)
            elif a.action=='create':result=life.create(spec,a.request_id,a.template)
            elif a.action=='attach':result=life.attach(a.branch,a.container)
            elif a.action=='running':result=life.running(a.branch)
            elif a.action=='status':result=dict(pool=backend.verify_pool(),manifest=s.data)
            elif a.action=='seal':result=life.seal(a.branch)
            elif a.action=='destroy':result=life.destroy(a.branch)
            elif a.action=='recover':result=life.recover()
            elif a.action=='gc':
                # No automatic result destruction, retries of ambiguous messages or forced unmount.
                if a.destroy_owned_pool:
                    backend.destroy_pool();result=s.data
                else:
                    result=dict(status='INSPECT_ONLY',recovery=life.recover(),
                        pending=[b['id'] for b in s.data['branches'].values() if b['state'] in ('DELETING','RECLAIM_PENDING')])
        print(json.dumps(result,indent=2))
    finally:s.close()


if __name__=='__main__':main()
