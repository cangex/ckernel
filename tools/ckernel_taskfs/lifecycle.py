# SPDX-License-Identifier: GPL-2.0
"""Each request gets a new thin ID and ext4 instance; no writable reuse."""
import json
import os
from pathlib import Path
import re
import shutil
import time
import uuid
from budget import host_gate,pool_gate
from identity import new_token,thin_id,token
from template import tree_digest,validate_spec


class Lifecycle:
    def __init__(self,store,backend):
        self.s=store;self.b=backend

    def gate(self,spec):
        if self.s.data['state']!='ACTIVE' or self.s.data['pending'] is not None:
            raise RuntimeError('pool not admitted')
        p=self.s.data['pool'];config=p['config']
        host_gate(shutil.disk_usage(self.s.root).free,config)
        live=[b for b in self.s.data['branches'].values() if b['state']!='DELETED']
        if any(b['state'] in ('ALLOCATING','DRAINING','FAILED','RECOVERY_REQUIRED') for b in live):
            raise RuntimeError('incomplete branch blocks new admission')
        pending=sum(b['state'] in ('DELETING','RECLAIM_PENDING','RECOVERY_REQUIRED','FAILED') for b in live)
        if pending>=config['max_pending']:raise RuntimeError('bounded reclamation backlog')
        reserved=sum(b['spec']['bytes'] for b in live)+sum(t['spec']['bytes'] for t in self.s.data['templates'].values())
        pool_gate(self.b.verify_pool(),reserved,spec['bytes'],config,len(live))

    def allocate_record(self,spec,request,kind,template_id):
        request=token(request);spec=validate_spec(spec)
        self.gate(spec)
        i=thin_id(self.s.data['next_id']);self.s.data['next_id']=i+1
        obj=dict(id=new_token(),request=request,thin_id=i,generation=i,kind=kind,
            spec=spec,template=template_id,state='ALLOCATING',fs_uuid=str(uuid.uuid4()),
            active=False,mounted=False,thin_created=False,formatted=False,
            times={'request_ns':time.monotonic_ns()},container=None)
        self.s.data['templates' if kind=='template' else 'branches'][obj['id']]=obj
        self.s.save();return obj

    def prepare_template(self,spec,request):
        if self.s.data['templates']:raise RuntimeError('one immutable template per prototype pool')
        obj=self.allocate_record(spec,request,'template',None)
        self.b.new_thin(obj);self.b.activate(obj);self.b.format(obj);self.b.mount(obj)
        obj['mounted']=True;self.s.save()
        def initialize():
            payload=Path(obj['mount'])/'payload';payload.mkdir(mode=0o755)
            fd=os.open(payload,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(fd)
            finally:os.close(fd)
        self.b.operation('template_initialize',obj,initialize,lambda:tree_digest(Path(obj['mount'])/'payload'))
        obj['tree']=tree_digest(Path(obj['mount'])/'payload')
        self.s.save();self.b.unmount(obj)
        self.b.operation('template_fsck',obj,
            lambda:self.b.run(['e2fsck','-fn','/dev/mapper/'+obj['name']]),lambda:self.b.fs_header(obj))
        self.b.remove_mapping(obj)
        obj['state']='SEALED';obj['times']['sealed_ns']=time.monotonic_ns();self.s.save()
        return obj

    def create(self,spec,request,template_id=None):
        request=token(request);spec=validate_spec(spec)
        for obj in self.s.data['branches'].values():
            if obj['request']==request:
                if obj['spec']!=spec or obj['template']!=template_id or obj['state'] not in ('READY','ATTACHED','RUNNING'):
                    raise RuntimeError('request conflict or incomplete request requires recovery')
                self.b.mount_identity(obj)
                return obj
        origin=None
        if template_id is not None:
            origin=self.s.data['templates'][token(template_id)]
            if origin['spec']!=spec or origin['state']!='SEALED' or origin['active'] or origin['mounted']:
                raise RuntimeError('template not immutable or geometry mismatch')
        obj=self.allocate_record(spec,request,'branch',template_id)
        self.b.new_thin(obj,origin);self.b.activate(obj)
        if origin is None:self.b.format(obj)
        else:self.b.reuuid(obj)
        self.b.mount(obj);obj['mounted']=True;self.s.save()
        payload=Path(obj['mount'])/'payload'
        if origin is None:
            self.b.operation('payload_initialize',obj,lambda:payload.mkdir(mode=0o755),lambda:tree_digest(payload))
        elif tree_digest(payload)!=origin['tree']:
            raise RuntimeError('snapshot payload tree mismatch')
        obj['payload']=str(payload);obj['state']='READY';obj['times']['ready_ns']=time.monotonic_ns();self.s.save()
        return obj

    def branch(self,branch_id):
        return self.s.data['branches'][token(branch_id)]

    def verify_template(self,template_id):
        obj=self.s.data['templates'][token(template_id)]
        if obj['state']!='SEALED' or obj['active'] or obj['mounted']:
            raise RuntimeError('template not sealed')
        self.b.activate(obj,readonly=True)
        header=self.b.fs_header(obj)
        if header.get('Filesystem state')!='clean':raise RuntimeError('template requires recovery')
        self.b.mount(obj,readonly=True);obj['mounted']=True;self.s.save()
        if tree_digest(Path(obj['mount'])/'payload')!=obj['tree']:
            raise RuntimeError('template changed')
        self.b.unmount(obj);self.b.remove_mapping(obj)
        obj['last_verified_ns']=time.monotonic_ns();self.s.save()
        return dict(status='PASS',template=obj['id'],scope='payload tree/xattrs plus clean superblock; not entire block-image equality')

    def bind_source(self,branch_id):
        obj=self.branch(branch_id)
        if obj['state']!='READY':raise RuntimeError('export requires ready branch')
        self.b.mount_identity(obj)
        pid=os.getpid()
        if os.readlink('/proc/self/ns/mnt')!=os.readlink('/proc/1/ns/mnt'):
            raise RuntimeError('Docker requires a host-visible source, not a proc-root symlink')
        source=obj['payload']
        left=Path(source).stat();right=Path(obj['payload']).stat()
        if (left.st_dev,left.st_ino)!=(right.st_dev,right.st_ino):
            raise RuntimeError('namespace export identity mismatch')
        obj['export']=dict(source=source,pid=pid,namespace=os.readlink('/proc/self/ns/mnt'),
            start_ticks=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()[19],
            payload_dev=left.st_dev,payload_ino=left.st_ino)
        self.s.save();return source

    def attach(self,branch_id,cid):
        obj=self.branch(branch_id)
        if obj['state']!='READY' or not re.fullmatch(r'[0-9a-f]{64}',cid):raise RuntimeError('attach state/identity')
        self.b.mount_identity(obj)
        row=json.loads(self.b.run(['docker','inspect',cid]))[0]
        labels=row['Config'].get('Labels') or {}
        if row['Id']!=cid or labels.get('cktaskfs.owner')!=self.s.data['owner'] or labels.get('cktaskfs.branch')!=obj['id']:
            raise RuntimeError('unregistered container')
        mounts=[m for m in row['Mounts'] if m['Destination']=='/usr/local/go']
        expected=obj.get('export',{}).get('source',obj['payload'])
        if len(mounts)!=1 or mounts[0]['Source']!=expected or not mounts[0]['RW']:
            raise RuntimeError('container branch bind mismatch')
        obj['container']=dict(id=cid,mount=mounts[0],created=row['Created'])
        obj['state']='ATTACHED';obj['times']['attached_ns']=time.monotonic_ns();self.s.save()
        return obj

    def running(self,branch_id):
        obj=self.branch(branch_id)
        if obj['state']!='ATTACHED':raise RuntimeError('running state')
        row=json.loads(self.b.run(['docker','inspect',obj['container']['id']]))[0]
        if not row['State']['Running'] or row['Created']!=obj['container']['created'] or ':container_t:' not in row['ProcessLabel']:
            raise RuntimeError('container generation/security')
        pid=row['State']['Pid'];ns=os.readlink(f'/proc/{pid}/ns/mnt')
        inside=Path(f'/proc/{pid}/root/usr/local/go').stat();outside=Path(obj['payload']).stat()
        if (inside.st_dev,inside.st_ino)!=(outside.st_dev,outside.st_ino):
            raise RuntimeError('container did not load registered filesystem')
        obj['container'].update(pid=pid,mount_namespace=ns,process_label=row['ProcessLabel'])
        obj['state']='RUNNING';obj['times']['running_ns']=time.monotonic_ns();self.s.save();return obj

    def drain(self,obj):
        if obj['state'] not in ('READY','ATTACHED','RUNNING','DRAINING'):
            raise RuntimeError('not drainable')
        # Refuse before changing state if a container/FD/mmap still references it.
        self.b.assert_no_references(obj,allow_host_mount=True)
        obj['state']='DRAINING';obj['times'].setdefault('drain_requested_ns',time.monotonic_ns());self.s.save()
        self.b.unmount(obj)
        self.b.operation('branch_fsck',obj,
            lambda:self.b.run(['e2fsck','-fn','/dev/mapper/'+obj['name']]),lambda:self.b.fs_header(obj))
        self.b.remove_mapping(obj)
        obj['times']['detached_ns']=time.monotonic_ns();self.s.save()

    def seal(self,branch_id):
        obj=self.branch(branch_id)
        if obj['state']=='SEALED':return obj
        self.drain(obj);obj['state']='SEALED';obj['times']['sealed_ns']=time.monotonic_ns();self.s.save();return obj

    def destroy(self,branch_id):
        obj=self.branch(branch_id)
        if obj['state']=='DELETED':return obj
        if obj['state']!='SEALED':self.drain(obj)
        obj['state']='DELETING';obj['times']['delete_requested_ns']=time.monotonic_ns();self.s.save()
        obj['state']='RECLAIM_PENDING';self.s.save();self.b.delete_thin(obj)
        obj['state']='DELETED';obj['times']['mapping_reclaimed_ns']=obj['reclaim']['mapping_reclaimed_ns'];self.s.save()
        return obj

    def recover(self):
        # Recovery is fail-closed: ambiguous non-idempotent thin messages are never replayed.
        pending=self.s.data['pending']
        checks=[]
        try:checks.append(dict(pool=self.b.verify_pool()))
        except Exception as e:checks.append(dict(error=str(e)))
        for obj in list(self.s.data['templates'].values())+list(self.s.data['branches'].values()):
            if obj.get('active'):
                try:checks.append(dict(id=obj['id'],mapping=self.b.verify_mapping(obj)))
                except Exception as e:checks.append(dict(id=obj['id'],error=str(e)))
        incomplete=[o['id'] for o in list(self.s.data['templates'].values())+list(self.s.data['branches'].values())
                    if o['state'] not in ('READY','ATTACHED','RUNNING','SEALED','DELETED')]
        report=dict(status='RECOVERY_REQUIRED' if pending or incomplete or self.s.data['boot']!=self.s.boot() or any('error' in c for c in checks) else 'CONSISTENT',
            incomplete=incomplete,
            pending=pending,observations=checks,automatic_mutation=False,
            limit='An ambiguous create_snap/delete/format or a boot change requires quarantined offline reconciliation, not blind retry.')
        self.s.data['last_recovery']=report;self.s.save();return report
