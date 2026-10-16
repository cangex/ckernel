#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Owned regular-file ext4 lifecycle. Never accepts a device to format."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import time
import uuid
from fs_domain_plan import GIB,layout

MARKER='ckernel-fs-domains-v1'

def run(args,timeout=120):
    p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
    if p.returncode:raise RuntimeError(json.dumps(dict(command=args,rc=p.returncode,stderr=p.stderr[-2000:])))
    return p.stdout

def save(path,data):
    tmp=path.with_suffix('.tmp')
    with tmp.open('x') as f:
        json.dump(data,f,indent=2);f.flush();os.fsync(f.fileno())
    tmp.rename(path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)

def record_identity(path):
    s=path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1:raise RuntimeError('image is not exclusive regular file')
    return dict(dev=s.st_dev,inode=s.st_ino,size=s.st_size)

def check_identity(path,expected):
    if record_identity(path)!=expected:raise RuntimeError('image identity changed')

def loop_identity(device,image):
    if not re.fullmatch(r'/dev/loop[0-9]+',device):raise RuntimeError('not a loop device')
    info=json.loads(run(['losetup','--json','--list','--output','NAME,BACK-FILE',device]))['loopdevices']
    if len(info)!=1 or info[0]['name']!=device or Path(info[0]['back-file']).resolve()!=image:
        raise RuntimeError('foreign loop backing')

class Manager:
    def __init__(self,root,create=False):
        given=Path(root).absolute()
        if given.is_symlink() or given!=given.resolve():raise RuntimeError('symlink path')
        self.root=given
        if create:
            self.root.mkdir(mode=0o700,parents=False,exist_ok=False)
            save(self.root/'manifest.json',dict(format=MARKER,owner=str(uuid.uuid4()),state='NEW',volumes=[],commands=[]))
        info=self.root.stat()
        if info.st_uid!=os.geteuid() or info.st_mode & 0o077:
            raise RuntimeError('state root must be owner-only')
        for name in ('manifest.json','lock'):
            path=self.root/name
            if path.is_symlink():raise RuntimeError('symlink state file')
            if path.exists() and (not path.is_file() or path.stat().st_nlink!=1):
                raise RuntimeError('nonexclusive state file')
        self.lock=(self.root/'lock').open('a')
        try:
            fcntl.flock(self.lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.state=json.loads((self.root/'manifest.json').read_text())
            if self.state.get('format')!=MARKER:raise RuntimeError('unowned directory')
            self.validate_state()
        except BaseException:
            self.lock.close();raise

    def close(self):self.lock.close()
    def validate_state(self):
        uuid.UUID(self.state['owner'])
        for i,v in enumerate(self.state['volumes']):
            if v['image']!=str(self.root/f'volume-{i}.img') or v['mount']!=str(self.root/f'mount-{i}'):
                raise RuntimeError('manifest path escapes owned layout')
            if Path(v['image']).is_symlink() or Path(v['mount']).is_symlink():
                raise RuntimeError('symlink volume path')
            if v.get('loop') and not re.fullmatch(r'/dev/loop[0-9]+',v['loop']):
                raise RuntimeError('invalid manifest device')
            uuid.UUID(v['uuid'])
    def persist(self):save(self.root/'manifest.json',self.state)
    def command(self,args,timeout=120):
        begin=time.monotonic_ns()
        try:
            out=run(args,timeout)
        except BaseException as e:
            self.state['commands'].append(dict(argv=args,begin_ns=begin,end_ns=time.monotonic_ns(),error=str(e)))
            self.persist();raise
        self.state['commands'].append(dict(argv=args,begin_ns=begin,end_ns=time.monotonic_ns(),output=out))
        self.persist();return out

    def create_volumes(self,specs):
        if self.state['state']!='NEW':raise RuntimeError('not empty')
        if not specs or len(specs)>48:raise ValueError('volume count')
        for i,spec in enumerate(specs):
            if spec['index']!=i or any(type(spec[k]) is not int or spec[k]<=0 for k in ('bytes','inodes','journal_mib')):
                raise ValueError('volume geometry')
            if spec['bytes']<128*1024**2 or spec['bytes']%4096 or spec['journal_mib']<16 or spec['journal_mib']*1024**2>spec['bytes']//4:
                raise ValueError('volume/journal size')
        required=sum(v['bytes'] for v in specs)+6*GIB+256*1024**2
        if shutil.disk_usage(self.root).free<required:raise RuntimeError('capacity floor')
        self.state['state']='CREATING';self.persist()
        for spec in specs:
            i=len(self.state['volumes']);image=self.root/f'volume-{i}.img';mount=self.root/f'mount-{i}'
            fd=os.open(image,os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_NOFOLLOW,0o600)
            try:os.posix_fallocate(fd,0,spec['bytes']);os.fsync(fd)
            finally:os.close(fd)
            v=dict(spec=spec,image=str(image),identity=record_identity(image),uuid=str(uuid.uuid4()),mount=str(mount),stage='ALLOCATED',loop=None)
            self.state['volumes'].append(v);self.persist()
            # mke2fs is permitted only on this freshly created owned regular file.
            check_identity(image,v['identity'])
            self.command(['mke2fs','-q','-F','-t','ext4','-b','4096','-I','256','-m','0',
                '-N',str(spec['inodes']),'-U',v['uuid'],'-L','ckfs-'+str(i),
                '-J','size='+str(spec['journal_mib']),'-E','lazy_itable_init=0,lazy_journal_init=0,nodiscard',str(image)])
            v['stage']='FORMATTED';self.persist()
            v['superblock']=self.command(['dumpe2fs','-h',str(image)])
            self.command(['e2fsck','-fn',str(image)])
            v['loop']=self.command(['losetup','--find','--show','--nooverlap',str(image)]).strip();self.persist()
            loop_identity(v['loop'],image);mount.mkdir(mode=0o700)
            self.command(['mount','-t','ext4','-o','rw,relatime,data=ordered',v['loop'],str(mount)])
            v['stage']='MOUNTED';self.persist();self.verify_volume(v)
        self.state['state']='ACTIVE';self.persist()

    def verify_volume(self,v):
        image=Path(v['image']);check_identity(image,v['identity']);loop_identity(v['loop'],image)
        rows=json.loads(self.command(['findmnt','-J','--mountpoint',v['mount'],'-o','TARGET,SOURCE,FSTYPE,OPTIONS,UUID']))['filesystems']
        if len(rows)!=1:raise RuntimeError('mount count')
        row=rows[0]
        if row['source']!=v['loop'] or row['fstype']!='ext4' or row['uuid']!=v['uuid']:raise RuntimeError('mount identity')
        if 'data=ordered' not in row['options'] or 'rw' not in row['options'].split(','):raise RuntimeError('mount semantics')
        v['mount_record']=row
        s=os.statvfs(v['mount']);v['capacity']=dict(blocks=s.f_blocks,free_blocks=s.f_bavail,block_size=s.f_frsize,inodes=s.f_files,free_inodes=s.f_favail)
        self.persist()

    def private_directory(self,slot,domain):
        if self.state['state']!='ACTIVE' or type(slot) is not int or not 0<=slot<48 or not 0<=domain<len(self.state['volumes']):raise RuntimeError('binding')
        if any(v['slot']==slot for v in self.state.get('bindings',[])):raise RuntimeError('slot already bound')
        v=self.state['volumes'][domain];self.verify_volume(v)
        d=Path(v['mount'])/f'slot-{slot}';d.mkdir(mode=0o755)
        self.state.setdefault('bindings',[]).append(dict(slot=slot,domain=domain,path=str(d),uuid=v['uuid']))
        self.persist();return d

    def remount(self):
        if self.state['state']!='DETACHED':raise RuntimeError('not detached')
        for v in self.state['volumes']:
            image=Path(v['image']);check_identity(image,v['identity'])
            if json.loads(run(['losetup','--json','--list','--associated',str(image)]))['loopdevices']:
                raise RuntimeError('unexpected attachment')
            v['loop']=self.command(['losetup','--find','--show','--nooverlap',str(image)]).strip();self.persist()
            loop_identity(v['loop'],image)
            self.command(['mount','-t','ext4','-o','rw,relatime,data=ordered',v['loop'],v['mount']])
            v['stage']='MOUNTED';self.persist();self.verify_volume(v)
        self.state['state']='ACTIVE';self.persist()

    def assert_unused(self,v):
        ids=run(['docker','ps','-aq']).split()
        if ids:
            for obj in json.loads(run(['docker','inspect',*ids])):
                for m in obj.get('Mounts',[]):
                    p=Path(m.get('Source','/'))
                    if p==Path(v['mount']) or Path(v['mount']) in p.parents:
                        raise RuntimeError('container still references mount '+obj['Id'])

    def assert_no_namespace_mount(self,device):
        s=os.stat(device);identity=f'{os.major(s.st_rdev)}:{os.minor(s.st_rdev)}'
        for entry in Path('/proc').iterdir():
            if not entry.name.isdigit():continue
            try:lines=(entry/'mountinfo').read_text().splitlines()
            except (FileNotFoundError,ProcessLookupError):continue
            for line in lines:
                if line.split()[2]==identity:
                    raise RuntimeError('remaining namespace mount '+entry.name)

    def teardown(self,delete=False):
        self.validate_state()
        self.state['state']='DRAINING';self.persist()
        for v in reversed(self.state['volumes']):
            image=Path(v['image']);mount=Path(v['mount'])
            if v['stage']=='REMOVED':continue
            check_identity(image,v['identity'])
            attached=json.loads(run(['losetup','--json','--list','--associated',str(image)]))['loopdevices']
            if not v['loop'] and attached:
                if len(attached)!=1:raise RuntimeError('ambiguous recovery loops')
                v['loop']=attached[0]['name'];self.persist()
            if v['loop']:
                loop_identity(v['loop'],image);self.assert_unused(v)
                if os.path.ismount(mount):
                    self.verify_volume(v);self.command(['sync','-f',str(mount)])
                    self.command(['umount',str(mount)])  # Never lazy or forced.
                self.assert_no_namespace_mount(v['loop'])
                self.command(['losetup','-d',v['loop']])
                if json.loads(run(['losetup','--json','--list','--associated',str(image)]))['loopdevices']:
                    raise RuntimeError('backing still in use')
                v['loop']=None;v['stage']='DETACHED';self.persist()
            if v['stage'] not in ('ALLOCATED','REMOVED'):
                self.command(['e2fsck','-fn',str(image)])
            self.command(['sync','-f',str(image)])
            v['stage']='DETACHED';self.persist()
            if delete:
                check_identity(image,v['identity']);image.unlink()
                if mount.exists():mount.rmdir()
                v['stage']='REMOVED';self.persist()
        self.state['state']='REMOVED' if delete else 'DETACHED';self.persist()

def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=('create','inspect','mount','teardown'));p.add_argument('root')
    p.add_argument('--domains',type=int,default=1);p.add_argument('--delete-owned-images',action='store_true');a=p.parse_args()
    m=Manager(a.root,create=a.action=='create')
    try:
        if a.action=='create':m.create_volumes(layout(a.domains))
        elif a.action=='mount':m.remount()
        elif a.action=='teardown':m.teardown(a.delete_owned_images)
        print(json.dumps(m.state,indent=2))
    finally:m.close()

if __name__=='__main__':main()
