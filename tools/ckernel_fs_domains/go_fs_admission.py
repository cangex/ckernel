#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Frozen Go trace on owned loop-ext4 outputs; correctness admission only."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import time
from fs_domain_lifecycle import Manager, run, save
from fs_domain_plan import GIB

BASE=Path('/root/ckernel-whitebox-baremetal-20261010_104800')
ROOT=Path('/root/ckernel-fs-domains-20261013/go-admission-r1')
SOURCE=BASE/'tac_runner_frozen.py'
SOURCE_SHA='4f78cbfe0afef2a47dfd9852f101ff237e9cdf339b049974f4e83e754893e716'
BOOT='e48d768b-1963-4b23-bad2-8db17de398cd'
KERNEL='6.6.0-wb-mmuobs-20261011'
LABEL='fs-domain-go-admission-20261013-r1'

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def freeze(m):
    if Path('/proc/sys/kernel/random/boot_id').read_text().strip()!=BOOT:raise RuntimeError('boot changed')
    if run(['uname','-r']).strip()!=KERNEL:raise RuntimeError('kernel changed')
    if run(['getenforce']).strip()!='Enforcing':raise RuntimeError('security changed')
    lsm=Path('/sys/kernel/security/lsm').read_text().strip().split(',')
    if 'selinux' not in lsm or 'apparmor' in lsm:raise RuntimeError('LSM changed')
    if json.loads(run(['docker','image','inspect',m.IMAGE]))[0]['Architecture']!='arm64':raise RuntimeError('image platform')

class Guard:
    def disk_usage(self,path):
        value=shutil.disk_usage(path)
        if value.free<6*GIB:raise RuntimeError('6GiB reserve')
        return value

def capacity(slots):
    free=shutil.disk_usage('/').free
    required=6*GIB+len(slots)*130*1024**2+512*1024**2
    if free<required:raise RuntimeError('capacity refused')
    return dict(free=free,required=required,images_already_allocated=True)

def load():
    if sha(SOURCE)!=SOURCE_SHA:raise RuntimeError('runner hash')
    spec=importlib.util.spec_from_file_location('frozen_go',SOURCE)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    # Read data constants, not the old boot-specific orchestration.
    tree=ast.parse((BASE/'go_native_off_v2.py').read_text())
    inputs=None
    for node in tree.body:
        if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='INPUTS' for t in node.targets):
            inputs=ast.literal_eval(node.value)
    if not inputs or len(inputs)!=7:raise RuntimeError('input manifest')
    for p,h in inputs.items():
        if sha(m.R/p)!=h:raise RuntimeError('input changed '+p)
    freeze(m)
    for slot in (0,12):
        node=slot//12;first=node*64+(slot%12)*4
        for cpu in (first,first+2):
            p=Path('/sys/devices/system/cpu/cpu'+str(cpu))
            if (p/'topology/thread_siblings_list').read_text().strip()!=f'{cpu}-{cpu+1}' or not (p/f'node{node}').exists():
                raise RuntimeError('topology changed')
    return m,inputs

def execute(m,name,slots):
    if run(['docker','ps','-q','--filter','label=wb.native']).strip():raise RuntimeError('another experiment active')
    parent=ROOT/name;parent.mkdir();manager=Manager(parent/'volumes',True)
    begin=time.monotonic_ns();raw=m.cmd;old_stats=m.stats
    paths={};created=[];result={'status':'FAIL','name':name}
    try:
        manager.create_volumes([dict(index=i,bytes=768*1024**2,inodes=32768,journal_mib=16) for i in range(len(slots))])
        paths={slot:manager.private_directory(slot,i) for i,slot in enumerate(slots)}
        setup_end=time.monotonic_ns()
        if len({p.stat().st_dev for p in paths.values()})!=len(slots):raise RuntimeError('filesystem not independent')
        calls=0
        def command(args,timeout=60,check=True):
            args=list(args)
            if args[:2]==['docker','create']:
                slot=int(args[args.index('--name')+1].rsplit('-',1)[1])
                args[2:2]=['--label','wb.native='+LABEL,'-v',str(paths[slot])+':/usr/local/go:Z']
            if args[:2] in (['docker','stop'],['docker','rm']):
                obj=json.loads(raw(['docker','inspect',args[-1]]).stdout)[0]
                if obj['Config']['Labels'].get('wb.native')!=LABEL:raise RuntimeError('foreign cleanup')
            q=raw(args,timeout=timeout,check=check)
            if args[:2]==['docker','create'] and q.returncode==0:created.append(q.stdout.strip())
            return q
        def stats(cgroup):
            nonlocal calls
            v=old_stats(cgroup);calls+=1
            if calls==len(slots):
                for slot in slots:
                    p=ROOT/'states'/name/str(slot)/'identity.json';x=json.loads(p.read_text())
                    x.update(storage='owned-loop-ext4-direct-bind',output_path=str(paths[slot]),scope='correctness admission only')
                    save(p,x)
            return v
        m.cmd=command;m.stats=stats;m.ROOT=ROOT;m.HOME_FROM=48
        m.shutil=Guard();m.capacity=capacity;m.freeze=lambda:freeze(m)
        row=m.state(name,slots,'off')
        if row['status']!='PASS':raise RuntimeError('official correctness')
        result.update(status='PASS',business=row,setup_ns=setup_end-begin,output_bytes={
            str(slot):int(run(['du','-sx','-B1',str(p)]).split()[0]) for slot,p in paths.items()},
            volumes=[dict(uuid=v['uuid'],spec=v['spec'],capacity=v['capacity'],mount=v['mount_record']) for v in manager.state['volumes']])
    except BaseException as e:
        result['error']=repr(e);raise
    finally:
        m.cmd=raw;m.stats=old_stats
        # All IDs came from this exclusive invocation; save final state before removal.
        for cid in created:
            p=raw(['docker','inspect',cid],check=False)
            if p.returncode:continue
            obj=json.loads(p.stdout)[0]
            if obj['Config']['Labels'].get('wb.native')!=LABEL:raise RuntimeError('cleanup identity')
            save(parent/(cid[:12]+'-final.json'),obj)
            if obj['State']['Running']:raw(['docker','stop','--time','3',cid])
            raw(['docker','rm',cid])
        drain=time.monotonic_ns()
        try:manager.teardown(True)
        finally:manager.close()
        result.update(teardown_ns=time.monotonic_ns()-drain,total_ns=time.monotonic_ns()-begin)
        save(parent/'result.json',result)
    freeze(m);return result

def main():
    os.umask(0o077);os.sched_setaffinity(0,{112,113,114,115});m,inputs=load()
    ROOT.mkdir();plan=[('solo-r1',[0]),('solo-r2',[0]),('solo-r3',[0]),('concurrent-r1',[0,12])]
    config=Path('/boot/config-'+KERNEL);image=Path('/boot/vmlinuz-'+KERNEL)
    if not config.is_file() or not image.is_file():raise RuntimeError('installed kernel artifacts missing')
    save(ROOT/'plan.json',dict(scope='F1 official correctness; NOT performance comparison',plan=plan,
        kernel=KERNEL,boot=BOOT,kernel_sha256=sha(image),config_sha256=sha(config),
        source_sha256=SOURCE_SHA,image=m.IMAGE,inputs=inputs,
        wrapper_sha256=sha(Path(__file__)),cache_rule='fresh container and fresh fully initialized filesystem; no global cache drop',
        backend='loop files on root ext4; physical disk shared; no bare block claim'))
    results=[]
    for name,slots in plan:
        results.append(execute(m,name,slots));save(ROOT/'progress.json',results)
    save(ROOT/'summary.json',dict(status='PASS',states=len(results),copies=sum(len(v['business']['instances']) for v in results),
        interpretation='Go official correctness only; no grouping or performance conclusion',results=results))

if __name__=='__main__':main()
