# SPDX-License-Identifier: GPL-2.0
"""Finite container bind correctness test; not a workload or performance run."""
import argparse
import json
from pathlib import Path
import time
from budget import GIB,MIB
from manifest import Store
from dm_backend import Backend
from lifecycle import Lifecycle
from identity import new_token

IMAGE='sha256:8809f4d92e1a03f4dc3a057b2de42b4b1a281c2774f43999dabad7926d0fa315'


def main():
    p=argparse.ArgumentParser();p.add_argument('root');p.add_argument('--execute-owned-files',action='store_true');a=p.parse_args()
    if not a.execute_owned_files:p.error('explicit execution required')
    s=Store(a.root,True,'container-integration');b=Backend(s);life=Lifecycle(s,b);cid=None
    result=dict(status='FAIL',scope='container bind and SELinux correctness only')
    try:
        if b.run(['docker','ps','-q']):raise RuntimeError('active containers')
        image=json.loads(b.run(['docker','image','inspect',IMAGE]))[0]
        if image['Architecture']!='arm64':raise RuntimeError('image architecture')
        b.prepare_pool(dict(data_bytes=4*GIB,metadata_bytes=64*MIB,chunk_sectors=128,max_branches=4,max_pending=2,root_floor=6*GIB))
        spec=dict(bytes=512*MIB,inodes=32768,journal_mib=16)
        template=life.prepare_template(spec,new_token());obj=life.create(spec,new_token(),template['id'])
        source=life.bind_source(obj['id'])
        script='while [ ! -f /usr/local/go/release ]; do sleep 0.02; done; printf taskfs > /usr/local/go/sentinel; sync -f /usr/local/go/sentinel'
        cid=b.run(['docker','create','--name','ctf-smoke-'+s.data['owner'],
            '--label','cktaskfs.owner='+s.data['owner'],'--label','cktaskfs.branch='+obj['id'],
            '--network','none','--cpuset-cpus','112-115','--cpuset-mems','1',
            '--memory','512m','--memory-swap','512m','--pids-limit','64',
            '-v',source+':/usr/local/go:Z','--entrypoint','/bin/sh',IMAGE,'-c',script])
        life.attach(obj['id'],cid);b.run(['docker','start',cid]);life.running(obj['id'])
        (Path(obj['payload'])/'release').write_text('correctness handshake, not business load')
        if b.run(['docker','wait',cid],timeout=30)!='0':raise RuntimeError('container failed')
        if (Path(obj['payload'])/'sentinel').read_text()!='taskfs':raise RuntimeError('sentinel missing')
        try:life.destroy(obj['id'])
        except RuntimeError as exc:
            if 'reference' not in str(exc):raise
        else:raise RuntimeError('stopped registered container did not block destroy')
        b.run(['docker','rm',cid]);cid=None
        life.verify_template(template['id']);life.destroy(obj['id']);b.destroy_pool()
        result.update(status='PASS',checks=['live container dev/inode matches branch','container_t with Enforcing',
            'write and fsync sentinel','stopped container reference refusal','template unchanged','normal full cleanup'])
    except BaseException as exc:
        result['error']=repr(exc);raise
    finally:
        if cid:
            row=json.loads(b.run(['docker','inspect',cid]))[0]
            if row['Config']['Labels'].get('cktaskfs.owner')!=s.data['owner']:raise RuntimeError('cleanup identity')
            if row['State']['Running']:b.run(['docker','stop','--time','3',cid])
            b.run(['docker','rm',cid])
        s.data['container_integration']=result;s.save();s.close();print(json.dumps(result))


if __name__=='__main__':main()
