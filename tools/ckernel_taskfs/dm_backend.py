# SPDX-License-Identifier: GPL-2.0
"""Privileged operations only on registered, file-backed taskfs objects."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import uuid
from budget import host_gate, parse_pool_status, validate_config
from identity import assert_regular, device, regular, thin_id, token


class Backend:
    def __init__(self, store):
        if os.geteuid() != 0:
            raise RuntimeError('real backend requires root; no sudo escalation')
        self.store = store

    def run(self, args, timeout=120):
        self.store.verify()
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        if p.returncode:
            raise RuntimeError(json.dumps(dict(argv=args, rc=p.returncode, stderr=p.stderr[-2000:])))
        return p.stdout.strip()

    def operation(self, action, obj, effect, observe):
        row = self.store.intent(action, obj['id'])
        try:
            effect()
            observation = observe()
            self.store.commit(row, observation)
            return observation
        except BaseException as exc:
            self.store.failure(row, exc)
            raise

    def info(self, name):
        if not re.fullmatch(r'ctf-[0-9a-f]{32}-(pool|[0-9]+)', name):
            raise ValueError('non-taskfs DM name')
        text = self.run(['dmsetup','info','-c','--noheadings','--separator','|','-o','name,uuid,major,minor,open',name])
        fields = [v.strip() for v in text.split('|')]
        if len(fields) != 5 or fields[0] != name:
            raise RuntimeError('ambiguous DM identity')
        return dict(name=fields[0], uuid=fields[1], dev=f'{int(fields[2])}:{int(fields[3])}', open=int(fields[4]))

    def verify_mapping(self, obj):
        info = self.info(obj['name'])
        if info['uuid'] != obj['dm_uuid'] or (obj.get('dev') is not None and info['dev'] != obj['dev']):
            raise RuntimeError('DM generation mismatch')
        text = self.run(['dmsetup','table',obj['name']])
        if text.split() != obj['table'].split():
            raise RuntimeError('DM table changed')
        if device('/dev/mapper/'+obj['name']) != info['dev']:
            raise RuntimeError('DM node mismatch')
        if 'thin_id' in obj and self.thin_aliases(obj) != [obj['name']]:
            raise RuntimeError('unregistered thin alias')
        return info

    def thin_aliases(self,obj):
        aliases=[]
        text=self.run(['dmsetup','table','--target','thin'])
        for line in text.splitlines():
            fields=line.split()
            if len(fields)>=6 and fields[3]=='thin' and fields[4]==self.store.data['pool']['dev'] and fields[5]==str(obj['thin_id']):
                aliases.append(fields[0].rstrip(':'))
        return sorted(aliases)

    def verify_backing(self, item):
        path = self.store.root/item['file']
        assert_regular(path, item['identity'])
        loop = item['loop']
        if not re.fullmatch(r'/dev/loop[0-9]+', loop):
            raise RuntimeError('foreign loop')
        rows = json.loads(self.run(['losetup','-J','-l','-O','NAME,BACK-FILE',loop]))['loopdevices']
        if len(rows) != 1 or rows[0]['name'] != loop or rows[0]['back-file'] != str(path):
            raise RuntimeError('loop backing mismatch')
        if device(loop) != item['dev']:
            raise RuntimeError('loop device changed')

    def verify_pool(self):
        p = self.store.data['pool']
        if not p:
            raise RuntimeError('no registered pool')
        for item in p['backing']:
            self.verify_backing(item)
        self.verify_mapping(p)
        return parse_pool_status(self.run(['dmsetup','status',p['name']]))

    def make_mapping(self, obj):
        def effect():
            args=['dmsetup','create',obj['name'],'--uuid',obj['dm_uuid'],'--table',obj['table']]
            if obj.get('readonly'):args.append('--readonly')
            self.run(args)
        def observe():
            info = self.verify_mapping(obj)
            obj['dev'] = info['dev']
            return info
        return self.operation('activate',obj,effect,observe)

    def prepare_pool(self, config):
        validate_config(config)
        if self.store.data['state'] != 'NEW':
            raise RuntimeError('pool preparation not retryable without recovery')
        if self.run(['getenforce']) != 'Enforcing':
            raise RuntimeError('SELinux must remain Enforcing')
        host_gate(shutil.disk_usage(self.store.root).free, config, allocate=True)
        owner = token(self.store.data['owner'])
        p = dict(id=owner, name='ctf-'+owner+'-pool', dm_uuid='CKTASKFS-'+owner+'-pool',
            config=config, backing=[], dev=None)
        self.store.data.update(pool=p,state='PREPARING');self.store.save()
        for role, size in [('metadata',config['metadata_bytes']),('data',config['data_bytes'])]:
            item = dict(file=role+'.img', role=role, bytes=size, loop=None)
            p['backing'].append(item);self.store.save()
            def allocate():
                fd = os.open(item['file'],os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_NOFOLLOW,0o600,dir_fd=self.store.fd)
                try:
                    os.posix_fallocate(fd,0,size);os.fsync(fd)
                finally:
                    os.close(fd)
                os.fsync(self.store.fd)
            def allocated():
                item['identity'] = regular(self.store.root/item['file'])
                if (self.store.root/item['file']).stat().st_blocks*512 < size:
                    raise RuntimeError('sparse outer backing forbidden')
                return item['identity']
            self.operation('allocate-'+role,p,allocate,allocated)
            def attach():
                assert_regular(self.store.root/item['file'],item['identity'])
                item['loop'] = self.run(['losetup','--find','--show','--nooverlap',str(self.store.root/item['file'])])
                item['dev'] = device(item['loop'])
                self.store.save()
            self.operation('loop-'+role,p,attach,lambda: self.verify_backing(item))
        md, data = p['backing']
        blocks = config['data_bytes']//(config['chunk_sectors']*512)
        p['table'] = f"0 {config['data_bytes']//512} thin-pool {md['dev']} {data['dev']} {config['chunk_sectors']} {max(1,blocks//20)} 2 no_discard_passdown error_if_no_space"
        self.store.save();self.make_mapping(p)
        p['initial_status'] = self.verify_pool()
        self.store.data['state']='ACTIVE';self.store.save()

    def new_thin(self, obj, origin=None):
        self.verify_pool();thin_id(obj['thin_id'])
        if origin is not None:
            if origin['state'] != 'SEALED' or origin.get('active'):
                raise RuntimeError('snapshot origin must be sealed and inactive')
            # All registered origin maps were removed; reject any name collision.
            if self.thin_aliases(origin):
                raise RuntimeError('origin unexpectedly active')
            message = f"create_snap {obj['thin_id']} {origin['thin_id']}"
        else:
            message = f"create_thin {obj['thin_id']}"
        self.operation('create_snap' if origin else 'create_thin',obj,
            lambda:self.run(['dmsetup','message',self.store.data['pool']['name'],'0',message]),
            lambda:dict(command_ack=True,verification='activation/readback follows; not filesystem correctness'))
        obj['thin_created']=True;self.store.save()

    def activate(self, obj, readonly=False):
        pool=self.store.data['pool'];self.verify_pool()
        if self.thin_aliases(obj):raise RuntimeError('existing thin mapping')
        obj['activation_generation']=obj.get('activation_generation',0)+1
        obj['readonly']=readonly;obj['dev']=None
        obj['name']='ctf-'+self.store.data['owner']+'-'+str(obj['thin_id'])
        obj['dm_uuid']='CKTASKFS-'+self.store.data['owner']+'-'+obj['id']+'-'+str(obj['activation_generation'])
        obj['table']=f"0 {obj['spec']['bytes']//512} thin {pool['dev']} {obj['thin_id']}"
        self.store.save();self.make_mapping(obj)
        if self.run(['blockdev','--getro','/dev/mapper/'+obj['name']])!=str(int(readonly)):
            raise RuntimeError('mapping read-only policy mismatch')
        obj['active']=True;self.store.save()

    def fs_header(self,obj):
        self.verify_mapping(obj)
        header=self.run(['dumpe2fs','-h','/dev/mapper/'+obj['name']])
        fields=dict(line.split(':',1) for line in header.splitlines() if ':' in line)
        fields={k:v.strip() for k,v in fields.items()}
        if fields.get('Filesystem UUID')!=obj['fs_uuid']:
            raise RuntimeError('ext4 identity mismatch')
        from template import validate_geometry
        validate_geometry(fields,obj['spec'])
        return fields

    def format(self,obj):
        if obj['state']!='ALLOCATING' or not obj['thin_created'] or obj.get('formatted'):
            raise RuntimeError('format only fresh registered thin device')
        spec=obj['spec'];path='/dev/mapper/'+obj['name']
        def effect():
            info=self.verify_mapping(obj)
            if info['open']:
                raise RuntimeError('format while device referenced')
            self.run(['mke2fs','-q','-t','ext4','-b','4096','-I','256','-m','0','-N',str(spec['inodes']),
                '-U',obj['fs_uuid'],'-J','size='+str(spec['journal_mib']),
                '-E','lazy_itable_init=0,lazy_journal_init=0,nodiscard',path])
        self.operation('format',obj,effect,lambda:self.fs_header(obj))
        obj['formatted']=True;self.store.save()

    def reuuid(self,obj):
        def effect():
            if self.verify_mapping(obj)['open']:
                raise RuntimeError('UUID change requires inactive filesystem')
            self.run(['tune2fs','-U',obj['fs_uuid'],'/dev/mapper/'+obj['name']])
        self.operation('branch_uuid',obj,effect,lambda:self.fs_header(obj))

    def mount(self,obj,readonly=False):
        mount=self.store.root/('mount-'+obj['id'])
        mount.mkdir(mode=0o700,exist_ok=True)
        if mount.is_symlink() or mount.resolve()!=mount:
            raise RuntimeError('unsafe mountpoint')
        propagation=self.run(['findmnt','-n','-o','PROPAGATION','--target',str(mount)])
        host_namespace=os.readlink('/proc/self/ns/mnt')==os.readlink('/proc/1/ns/mnt')
        if propagation != 'private' and not (propagation=='shared' and host_namespace):
            raise RuntimeError('unsupported mount propagation context')
        obj['propagation']=propagation
        obj['mount']=str(mount);self.store.save()
        def effect():
            self.verify_mapping(obj)
            self.run(['mount','-t','ext4','-o',('ro' if readonly else 'rw')+',relatime,data=ordered','/dev/mapper/'+obj['name'],str(mount)])
        self.operation('mount',obj,effect,lambda:self.mount_identity(obj))

    def mount_identity(self,obj):
        self.verify_mapping(obj)
        rows=json.loads(self.run(['findmnt','-J','--mountpoint',obj['mount'],'-o','TARGET,SOURCE,FSTYPE,OPTIONS,MAJ:MIN,ID']))['filesystems']
        if len(rows)!=1:
            raise RuntimeError('mount count')
        r=rows[0]
        if r['target']!=obj['mount'] or r['fstype']!='ext4' or r['maj:min']!=obj['dev'] or 'data=ordered' not in r['options']:
            raise RuntimeError('mount mismatch')
        obj['mount_identity']=dict(id=r['id'],namespace=os.readlink('/proc/self/ns/mnt'),dev=obj['dev'])
        sysname=Path('/sys/dev/block/'+obj['dev']).resolve(strict=True).name
        obj['journal_interfaces']=[p.name for p in Path('/proc/fs/jbd2').iterdir() if p.name.startswith(sysname+'-')]
        if len(obj['journal_interfaces'])!=1:
            raise RuntimeError('independent journal interface not identified')
        return r

    def assert_no_references(self,obj,allow_host_mount=False,recover_propagated=False):
        wanted=obj['dev'];hostns=os.readlink('/proc/self/ns/mnt')
        approved=set()
        if recover_propagated or (allow_host_mount and obj.get('propagation')=='shared'):
            from mount_guard import inventory, mirrors
            approved=mirrors(inventory(wanted),hostns,obj['mount_identity']['id'],wanted,obj['mount'])
        ids=self.run(['docker','ps','-aq']).split()
        if ids:
            for container in json.loads(self.run(['docker','inspect',*ids])):
                labels=container['Config'].get('Labels') or {}
                if labels.get('cktaskfs.owner')==self.store.data['owner'] and labels.get('cktaskfs.branch')==obj['id']:
                    raise RuntimeError('registered container still references branch')
                for m in container.get('Mounts',[]):
                    source=Path(m.get('Source','/'))
                    if str(source)==obj.get('export',{}).get('source') or source==Path(obj['mount']) or Path(obj['mount']) in source.parents:
                        raise RuntimeError('container still references branch')
        for p in Path('/proc').iterdir():
            if not p.name.isdigit():continue
            try:
                namespace=os.readlink(p/'ns/mnt')
                lines=(p/'mountinfo').read_text().splitlines()
                for line in lines:
                    if line.split()[2]==wanted and not ((namespace,line.split()[0]) in approved or (allow_host_mount and namespace==hostns and line.split()[4]==obj['mount'])):
                        raise RuntimeError('remaining mount namespace reference')
                for link in list((p/'fd').iterdir())+[p/'cwd',p/'root',p/'exe']:
                    try:
                        st=link.stat()
                        if f'{os.major(st.st_dev)}:{os.minor(st.st_dev)}'==wanted:
                            raise RuntimeError('open filesystem reference')
                    except (FileNotFoundError,ProcessLookupError):pass
                for line in (p/'maps').read_text().splitlines():
                    parts=line.split()
                    dev=parts[3].split(':')
                    if f'{int(dev[0],16)}:{int(dev[1],16)}'==wanted:
                        raise RuntimeError('remaining mmap reference')
            except (FileNotFoundError,ProcessLookupError):continue

    def unmount(self,obj):
        self.mount_identity(obj);self.assert_no_references(obj,allow_host_mount=True)
        def effect():
            self.run(['sync','-f',obj['mount']]);self.run(['umount',obj['mount']])
        self.operation('unmount',obj,effect,lambda:self.assert_no_references(obj))
        obj['mounted']=False;self.store.save()

    def recover_propagated_unmount(self,obj):
        # Only normal host unmount of verified propagated mirrors. Other
        # namespaces are never entered; surviving references fail closed.
        self.mount_identity(obj)
        self.assert_no_references(obj,recover_propagated=True)
        def effect():
            self.run(['sync','-f',obj['mount']])
            self.run(['umount',obj['mount']])
        self.operation('recover_propagated_unmount',obj,effect,lambda:self.assert_no_references(obj))
        obj['mounted']=False;self.store.save()

    def remove_mapping(self,obj):
        self.assert_no_references(obj)
        def effect():
            if self.verify_mapping(obj)['open']:
                raise RuntimeError('DM mapping still open')
            self.run(['dmsetup','remove',obj['name']])
        def observe():
            names=self.run(['dmsetup','info','-c','--noheadings','-o','uuid']).split()
            if obj['dm_uuid'] in names:
                raise RuntimeError('mapping still exists')
            return dict(mapping_absent=True)
        self.operation('remove',obj,effect,observe)
        obj['active']=False;self.store.save()

    def delete_thin(self,obj):
        if obj['active'] or obj['mounted'] or obj['state']!='RECLAIM_PENDING':
            raise RuntimeError('branch not drained')
        before=self.verify_pool()
        self.operation('delete',obj,
            lambda:self.run(['dmsetup','message',self.store.data['pool']['name'],'0',f"delete {thin_id(obj['thin_id'])}"]),
            lambda:dict(pool=self.verify_pool(),logical_delete_ack=True,
                outer_capacity_returned=False,reason='no_discard_passdown; backing remains reserved'))
        obj['reclaim']=dict(before=before,after=self.verify_pool(),mapping_reclaimed_ns=time.monotonic_ns(),
            level='DM mapping absent and thin delete acknowledged; aggregate pool counters recorded, outer files retained')
        self.store.save()

    def destroy_pool(self):
        s=self.store.data;p=s['pool']
        if s['pending'] or any(o['state']!='DELETED' for o in s['branches'].values()):
            raise RuntimeError('live or unresolved branches')
        self.verify_pool()
        for obj in s['templates'].values():
            if obj['state']!='SEALED' or obj['active'] or obj['mounted'] or self.thin_aliases(obj):
                raise RuntimeError('template has references or unresolved state')
            obj['state']='RECLAIM_PENDING';self.store.save();self.delete_thin(obj)
            obj['state']='DELETED';self.store.save()
        def remove():
            if self.verify_mapping(p)['open']:raise RuntimeError('pool still open')
            self.run(['dmsetup','remove',p['name']])
        def absent():
            if p['dm_uuid'] in self.run(['dmsetup','info','-c','--noheadings','-o','uuid']).split():
                raise RuntimeError('pool still active')
            return dict(pool_absent=True)
        self.operation('remove_pool',p,remove,absent)
        md=p['backing'][0];self.verify_backing(md)
        self.operation('check_inactive_metadata',p,
            lambda:self.run(['thin_check',md['loop']],timeout=120),lambda:dict(inactive_metadata_check='PASS'))
        for item in reversed(p['backing']):
            self.verify_backing(item)
            if list(Path('/sys/dev/block/'+item['dev']+'/holders').iterdir()):
                raise RuntimeError('backing loop has holders')
            path=self.store.root/item['file']
            for process in Path('/proc').iterdir():
                if not process.name.isdigit():continue
                try:
                    for fd in (process/'fd').iterdir():
                        try:
                            st=fd.stat()
                            if (st.st_dev,st.st_ino)==(item['identity']['dev'],item['identity']['ino']):
                                raise RuntimeError('backing file has userspace reference')
                            if st.st_rdev and f'{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}'==item['dev']:
                                raise RuntimeError('loop device has userspace reference')
                        except (FileNotFoundError,ProcessLookupError):pass
                except (FileNotFoundError,ProcessLookupError):pass
            def detach():self.run(['losetup','-d',item['loop']])
            def detached():
                rows=json.loads(self.run(['losetup','-J','-l','-O','NAME,BACK-FILE']))['loopdevices']
                if any(r['back-file']==str(path) for r in rows):
                    raise RuntimeError('loop detach incomplete')
                return dict(loop_absent=True)
            self.operation('detach-'+item['role'],p,detach,detached)
            def unlink():
                assert_regular(path,item['identity']);path.unlink();os.fsync(self.store.fd)
            self.operation('unlink-'+item['role'],p,unlink,lambda:dict(file_absent=not path.exists()))
        s['state']='DELETED';p['final_host_free']=shutil.disk_usage(self.store.root).free;self.store.save()
