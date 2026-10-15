# SPDX-License-Identifier: GPL-2.0
"""Frozen Go replay adapter. New filesystems for every state; no recycling.

Admission execution is not a formal matrix or VM fault acceptance. Scoring
retains the filesystem; its time is recorded and not disguised as immediate
production deletion latency.
"""
import json
import os
from pathlib import Path
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ckernel_fs_domains'))
import go_fs_admission as reference
from budget import GIB,MIB
from costs import CompletionWindow
from identity import new_token


def geometry(condition,n):
    if condition not in ('S','G','F','B') or n not in (1,24):raise ValueError('frozen conditions only')
    groups={'S':1,'G':2,'F':n,'B':n}[condition]
    divisor={'S':1,'G':2,'F':24,'B':24}[condition]
    return [dict(bytes=18*GIB//divisor,inodes=787968//divisor,journal_mib=384//divisor) for _ in range(groups)]


def phase_snapshot():
    return dict(at_ns=time.monotonic_ns(),cpu=Path('/proc/stat').read_text(),
        memory=Path('/proc/meminfo').read_text(),disk=Path('/proc/diskstats').read_text(),
        self_usage=list(os.times()))


def execute(module,store,backend,life,root,name,condition,n,template=None):
    slots=list(range(n));specs=geometry(condition,n)
    if condition=='B' and template is None:raise ValueError('snapshot template required')
    parent=root/name;parent.mkdir()
    raw,old_stats=module.cmd,module.stats
    objects=[];paths={};created={};cgroups={};window=None;before_calls=0;after_ready=False
    result=dict(status='FAIL',scope='correctness admission, NOT formal net benefit',condition=condition,n=n,
        request_ns=time.monotonic_ns(),phase_before_setup=phase_snapshot())
    try:
        if backend.run(['docker','ps','-q']):raise RuntimeError('other containers active')
        for spec in specs:
            objects.append(life.create(spec,new_token(),template if condition=='B' else None))
        for slot in slots:
            index=slot%len(objects);obj=objects[index]
            payload=Path(obj['payload'])
            if condition in ('S','G'):
                payload=payload/('task-'+str(slot));payload.mkdir(mode=0o755)
            paths[slot]=payload
        result.update(setup_end_ns=time.monotonic_ns(),phase_after_setup=phase_snapshot(),
                      objects=[o['id'] for o in objects])

        def snapshot():
            for slot,(cg,inode) in cgroups.items():
                if cg.stat().st_ino!=inode:raise RuntimeError('cgroup generation changed')
            return dict(cgroups={str(k):old_stats(v[0]) for k,v in cgroups.items()},system=phase_snapshot())

        def command(args,timeout=60,check=True):
            nonlocal after_ready
            args=list(args)
            if args[:2]==['docker','create']:
                slot=int(args[args.index('--name')+1].rsplit('-',1)[1]);obj=objects[slot%len(objects)]
                args[2:2]=['--label','cktaskfs.owner='+store.data['owner'],
                    '--label','cktaskfs.branch='+obj['id'],'-v',str(paths[slot])+':/usr/local/go:Z']
            if args[:2] in (['docker','stop'],['docker','rm']):
                if args[-1] not in created:raise RuntimeError('foreign container cleanup refused')
                row=json.loads(raw(['docker','inspect',args[-1]]).stdout)[0]
                if row['Config']['Labels'].get('cktaskfs.owner')!=store.data['owner']:raise RuntimeError('cleanup ownership changed')
            if args[:3]==['docker','inspect','--size'] and not after_ready:
                if window is None:raise RuntimeError('completion window missing')
                result['cost_window']=window.finish_before_grading();after_ready=True
                result['grading_begin_ns']=time.monotonic_ns()
            value=raw(args,timeout=timeout,check=check)
            if args[:2]==['docker','create'] and value.returncode==0:
                cid=value.stdout.strip();created[cid]=slot
                row=json.loads(raw(['docker','inspect',cid]).stdout)[0]
                mounts=[x for x in row['Mounts'] if x['Destination']=='/usr/local/go']
                if len(mounts)!=1 or mounts[0]['Source']!=str(paths[slot]) or not mounts[0]['RW']:
                    raise RuntimeError('created container bind mismatch')
                obj.setdefault('batch_bindings',[]).append(dict(id=cid,slot=slot,created=row['Created'],
                    payload=str(paths[slot]),attached_ns=time.monotonic_ns()))
                if obj['state']=='READY':obj['state']='ATTACHED'
                store.save()
            if args[:2]==['docker','start'] and value.returncode==0:
                cid=args[-1];slot=created[cid]
                row=json.loads(raw(['docker','inspect',cid]).stdout)[0]
                inside=Path(f"/proc/{row['State']['Pid']}/root/usr/local/go").stat();outside=paths[slot].stat()
                if (inside.st_dev,inside.st_ino)!=(outside.st_dev,outside.st_ino):raise RuntimeError('wrong task filesystem')
                if ':container_t:' not in row['ProcessLabel']:raise RuntimeError('container security label')
                obj=objects[slot%len(objects)]
                binding=next(x for x in obj['batch_bindings'] if x['id']==cid)
                if binding['created']!=row['Created']:raise RuntimeError('container generation mismatch')
                binding.update(process_label=row['ProcessLabel'],dev=inside.st_dev,ino=inside.st_ino,
                    running_ns=time.monotonic_ns(),namespace=os.readlink(f"/proc/{row['State']['Pid']}/ns/mnt"))
                obj['state']='RUNNING'
                store.save()
            return value

        def stats(cg):
            nonlocal before_calls,window
            if after_ready:
                slot=next(k for k,v in cgroups.items() if v[0]==cg)
                return result['cost_window']['after']['cgroups'][str(slot)]
            value=old_stats(cg);before_calls+=1
            if before_calls==n:
                state=root/'states'/name
                for slot in slots:
                    identity=json.loads((state/str(slot)/'identity.json').read_text())
                    path=Path('/sys/fs/cgroup'+identity['cgroup'])
                    cgroups[slot]=(path,identity['cgroup_inode'])
                window=CompletionWindow([state/str(slot)/'evidence' for slot in slots],snapshot)
                window.start()
            return value

        module.cmd=command;module.stats=stats;module.ROOT=root;module.HOME_FROM=48
        module.shutil=reference.Guard();module.capacity=reference.capacity;module.freeze=lambda:reference.freeze(module)
        result['business']=module.state(name,slots,'off')
        result['grading_end_ns']=time.monotonic_ns()
        if result['business']['status']!='PASS':raise RuntimeError('business correctness rejected')
        result['status']='PASS'
    except BaseException as exc:
        result['error']=repr(exc);raise
    finally:
        module.cmd=raw;module.stats=old_stats
        # Frozen runner removes successful containers. Retain failed branches;
        # do not force cleanup while references or incomplete states remain.
        result['retention_and_cleanup_begin_ns']=time.monotonic_ns()
        try:
            if result['status']=='PASS':
                for obj in objects:life.destroy(obj['id'])
        except BaseException as exc:
            result.update(status='FAIL',cleanup_error=repr(exc));raise
        finally:
            result.update(turnover_end_ns=time.monotonic_ns(),phase_after=phase_snapshot(),
                cost_limits=['system counters include unrelated background work',
                             'memory counters not yet unique-physical accounting',
                             'turnover includes official scoring retention; not immediate production deletion'])
            with (parent/'result.json').open('x') as stream:json.dump(result,stream,indent=2)
    return result
