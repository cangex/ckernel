# SPDX-License-Identifier: GPL-2.0
"""Bounded configuration observations, never inferred holders or contention.

Read only at session boundaries. PID, namespace and cgroup associations are
checked at both ends of each read. Endpoint agreement is not continuity.
"""
import errno
import os
from pathlib import Path
import re
import time

from periodic_plan import digest

SCHEMA = 'cis-resource-topology-v1'
LIMITS = dict(cgroups=32, depth=8, tasks=8, mounts=128, ancestors=32,
              bytes=256 << 10, reads=256, wall_ns=25_000_000)
CONFIG = ('cpu.max', 'memory.max', 'memory.high', 'cpuset.cpus.effective',
          'cpuset.mems.effective')
FINGERPRINT_FIELDS = ('schema','id','generation','identity_valid','ancestors',
                      'tasks','devices','status')
MOUNT_OPTIONS = frozenset(('ro','rw','nosuid','nodev','noexec','relatime',
                           'noatime','strictatime','lazytime','sync','dirsync'))


class Bound(Exception):
    pass


class Reader:
    def __init__(self, clock=time.monotonic_ns):
        self.clock = clock
        self.start = clock()
        self.cpu_start = time.thread_time_ns()
        self.bytes = self.reads = 0

    def check(self):
        if self.clock()-self.start > LIMITS['wall_ns']:
            raise Bound('wall_budget')
        if self.reads >= LIMITS['reads'] or self.bytes >= LIMITS['bytes']:
            raise Bound('read_budget')

    def read(self, path, maximum=4096, dir_fd=None):
        self.check()
        self.reads += 1
        maximum = min(maximum, LIMITS['bytes']-self.bytes)
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                     dir_fd=dir_fd)
        try:
            value = os.read(fd, maximum+1)
        finally:
            os.close(fd)
        self.bytes += len(value)
        if len(value) > maximum:
            raise Bound('file_capacity')
        return value.decode('utf-8', errors='strict').strip()

    def stats(self):
        return dict(begin_ns=self.start, end_ns=self.clock(), reads=self.reads,
                    bytes=self.bytes, thread_cpu_ns=time.thread_time_ns()-self.cpu_start)


def id_of(fd):
    value = os.fstat(fd)
    return [value.st_dev, value.st_ino]


def task_start(text):
    end = text.rfind(')')
    words = text[end+1:].split()
    if end < 0 or len(words) < 20 or not words[19].isdigit():
        raise ValueError('task_stat')
    return int(words[19])


def cgroup_path(text):
    rows = [line[3:] for line in text.splitlines() if line.startswith('0::/')]
    if len(rows) != 1 or '..' in Path(rows[0]).parts:
        raise ValueError('cgroup_v2_path')
    return rows[0]


def unescape(word):
    # mountinfo escapes only these four bytes. Do not interpret arbitrary codes.
    return re.sub(r'\\(040|011|012|134)',
                  lambda m: {'040':' ', '011':'\t', '012':'\n', '134':'\\'}[m[1]], word)


def parse_mounts(text):
    result = []
    for line in text.splitlines():
        if len(result) == LIMITS['mounts']:
            raise Bound('mount_capacity')
        left, sep, right = line.partition(' - ')
        a, b = left.split(), right.split()
        if not sep or len(a) < 6 or len(b) < 3 or not re.fullmatch(r'\d+:\d+', a[2]):
            raise ValueError('mountinfo_schema')
        if not all(v.isdigit() for v in a[:2]):
            raise ValueError('mountinfo_identity')
        result.append(dict(mount_id=int(a[0]), parent_id=int(a[1]), device=a[2],
            root=unescape(a[3]), mountpoint=unescape(a[4]), options=sorted(set(a[5].split(','))&MOUNT_OPTIONS),
            fs=b[0], super_options=sorted(set(b[2].split(','))&MOUNT_OPTIONS),
            relation='configured_mount_not_access_or_same_inode'))
    return result


def parse_list(text):
    # Keep ranges rather than expanding to a container-by-CPU matrix.
    if not text:
        return []
    result = []
    for word in text.split(','):
        if not re.fullmatch(r'\d+(?:-\d+)?', word) or len(result) >= 4096:
            raise ValueError('cpu_or_node_range')
        bounds = [int(v) for v in word.split('-')]
        start, end = bounds[0], bounds[-1]
        if start > end or end > 1048575 or result and start <= result[-1][1]:
            raise ValueError('cpu_or_node_range_order')
        result.append([start, end])
    return result


def inspect_task(reader, pid, root_path, *, proc=Path('/proc'), cgroup=Path('/sys/fs/cgroup')):
    reader.check()
    fd = os.open(proc/str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        def identity():
            start = task_start(reader.read('stat', dir_fd=fd))
            group = cgroup_path(reader.read('cgroup', dir_fd=fd))
            namespaces = {name: os.readlink('ns/'+name, dir_fd=fd) for name in ('mnt','net')}
            status = reader.read('status',16384,dir_fd=fd)
            affinity = {}
            for line in status.splitlines():
                key, sep, value = line.partition(':')
                if sep and key in ('Cpus_allowed_list','Mems_allowed_list'):
                    affinity[key] = parse_list(value.strip())
            if len(affinity) != 2:
                raise ValueError('task_affinity_unknown')
            return dict(pid=pid, start_ticks=start, cgroup=group, namespaces=namespaces,affinity=affinity)
        before = identity()
        path = str(cgroup)+before['cgroup']
        if path != root_path and not path.startswith(root_path+'/'):
            raise ValueError('task_outside_root')
        mounts = parse_mounts(reader.read('mountinfo', 65536, dir_fd=fd))
        interfaces = []
        for line in reader.read('net/dev', 16384, dir_fd=fd).splitlines()[2:]:
            name, sep, unused = line.partition(':')
            if not sep or len(interfaces) >= 64:
                raise Bound('network_interface_capacity')
            interfaces.append(name.strip())
        after = identity()
        if before != after:
            raise ValueError('task_moved_or_reused')
        return dict(before, mounts=mounts, interfaces=sorted(interfaces),
                    lifetime='boundary_observation_only',
                    network_scope='namespace_local_names; veth_peer_and_NIC_queue_unknown')
    finally:
        os.close(fd)


def collect(root, clock=time.monotonic_ns, *, proc=Path('/proc'),
            cgroup=Path('/sys/fs/cgroup'), sys=Path('/sys')):
    reader = Reader(clock)
    result = dict(schema=SCHEMA, id=root['id'], generation=root['generation'],
        identity_valid=False, ancestors=[], tasks=[], devices=[], errors=[], limits=LIMITS,
        scope='bounded_configuration_only; no observed_contention_or_holder',
        coverage=dict(cgroups=0, tasks_attempted=0, tasks_accepted=0, capped=False))
    queue = []
    try:
        if (os.fstat(root['fd']).st_ino != root['id'] or
                os.readlink(proc/'self/fd'/str(root['fd'])) != root['path'] or
                not Path(root['path']).is_relative_to(cgroup) or
                os.fstat(root['fd']).st_dev != os.stat(cgroup).st_dev):
            raise ValueError('root_identity')
        result['identity_valid'] = True
        parent = os.dup(root['fd'])
        try:
            for unused in range(LIMITS['ancestors']):
                reader.check()
                path = os.readlink(proc/'self/fd'/str(parent))
                config = {}
                for name in CONFIG:
                    try:
                        config[name] = reader.read(name, dir_fd=parent)
                    except OSError as e:
                        if e.errno != errno.ENOENT:
                            raise
                result['ancestors'].append(dict(identity=id_of(parent), path=path, config=config))
                if path == str(cgroup):
                    break
                if not Path(path).is_relative_to(cgroup):
                    raise ValueError('ancestor_escape')
                next_fd = os.open('..', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
                os.close(parent)
                parent = next_fd
            else:
                raise Bound('ancestor_capacity')
        finally:
            os.close(parent)
        queue.append((os.dup(root['fd']), 0))
        pids = set()
        while queue:
            reader.check()
            fd, depth = queue.pop(0)
            try:
                result['coverage']['cgroups'] += 1
                for word in reader.read('cgroup.procs', dir_fd=fd).splitlines():
                    if not word.isdigit() or int(word) <= 0:
                        raise ValueError('cgroup_process_list')
                    if int(word) in pids:
                        continue
                    if len(pids) == LIMITS['tasks']:
                        raise Bound('task_capacity')
                    pids.add(int(word))
                    result['coverage']['tasks_attempted'] += 1
                    try:
                        result['tasks'].append(inspect_task(reader,int(word),root['path'],proc=proc,cgroup=cgroup))
                    except (OSError, ValueError, UnicodeError) as e:
                        result['errors'].append(dict(scope='task', pid=int(word), error=str(e)))
                with os.scandir(fd) as entries:
                    for entry in entries:
                        reader.check()
                        if not entry.is_dir(follow_symlinks=False):
                            continue
                        if depth == LIMITS['depth'] or len(queue)+result['coverage']['cgroups'] >= LIMITS['cgroups']:
                            raise Bound('descendant_capacity')
                        child = os.open(entry.name,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=fd)
                        queue.append((child,depth+1))
            finally:
                os.close(fd)
        devices = sorted({m['device'] for task in result['tasks'] for m in task['mounts']})
        for device in devices:
            reader.check()
            link = sys/'dev/block'/device
            if not link.exists():
                continue
            resolved = link.resolve()
            if not resolved.is_relative_to(sys/'devices'):
                raise ValueError('device_sysfs_escape')
            path = resolved
            while not (path/'queue').exists() and path != sys/'devices':
                reader.check()
                path = path.parent
            sequence = None
            try:
                sequence = reader.read(path/'diskseq')
                if not sequence.isdigit():
                    raise ValueError('device_diskseq')
            except FileNotFoundError:
                pass
            # sysfs path is a configuration key, never a request_queue pointer.
            result['devices'].append(dict(device=device, sysfs=str(resolved), diskseq=sequence,
                queue_sysfs=str(path/'queue') if (path/'queue').exists() else None,
                lifetime='diskseq_endpoints' if sequence else 'UNKNOWN',
                stacked_backends='UNRESOLVED'))
        if (os.fstat(root['fd']).st_ino != root['id'] or
                os.readlink(proc/'self/fd'/str(root['fd'])) != root['path']):
            raise ValueError('root_changed')
        reader.check()
    except Bound as e:
        result['coverage']['capped'] = True
        result['errors'].append(dict(scope='budget',error=str(e)))
    except (OSError, ValueError, UnicodeError) as e:
        result['errors'].append(dict(scope='identity_or_configuration',error=str(e)))
        result['identity_valid'] = False
    finally:
        for fd, unused in queue:
            os.close(fd)
    result['coverage']['tasks_accepted'] = len(result['tasks'])
    result['status'] = ('IDENTITY_UNKNOWN' if not result['identity_valid'] else
                        'PARTIAL' if result['errors'] else 'OBSERVED_ENDPOINT')
    result['read_cost'] = reader.stats()
    result['fingerprint'] = digest({k: result[k] for k in FINGERPRINT_FIELDS})
    return result


def stable(before, after):
    if not before or not after:
        return dict(status='UNOBSERVED', candidates=[], evidence='CONFIGURATION_ONLY')
    for value in (before,after):
        if value.get('fingerprint') != digest({k: value.get(k) for k in FINGERPRINT_FIELDS}):
            raise ValueError('topology_fingerprint')
    if (before.get('schema') != SCHEMA or after.get('schema') != SCHEMA or
            before.get('status') != 'OBSERVED_ENDPOINT' or after.get('status') != 'OBSERVED_ENDPOINT'):
        return dict(status='PARTIAL_OR_UNKNOWN', candidates=[], evidence='CONFIGURATION_ONLY')
    if before['fingerprint'] != after['fingerprint']:
        return dict(status='CHANGED_INVALIDATED', candidates=[], evidence='CONFIGURATION_ONLY')
    candidates = []
    for row in before['ancestors']:
        candidates.append(dict(kind='cgroup_ancestor', key=row['identity'],path=row['path']))
    for row in before['devices']:
        if row['diskseq']:
            candidates.append(dict(kind='block_device',key=[row['device'],row['diskseq']],
                                   queue_sysfs=row['queue_sysfs']))
    mounts = sorted({(m['fs'],m['device']) for task in before['tasks'] for m in task['mounts']})
    for fs, device in mounts:
        if fs in ('ext4','xfs','btrfs','tmpfs'):
            candidates.append(dict(kind='filesystem_backend',key=[fs,device],
                                   lifetime='snapshot_only_not_superblock_lifetime'))
    config = before['ancestors'][0]['config'] if before['ancestors'] else {}
    return dict(status='STABLE_ENDPOINTS', fingerprint=before['fingerprint'],candidates=candidates,
                allowed_cpus=parse_list(config.get('cpuset.cpus.effective','')),
                allowed_nodes=parse_list(config.get('cpuset.mems.effective','')),
                evidence='CONFIGURATION_ONLY', continuous_lifetime_proven=False,
                caution='No container access, waiting, holder or interference inferred')


def compare_roots(boundary_before, boundary_after):
    contexts = {key: stable(row.get('topology'),boundary_after.get(key,{}).get('topology'))
                for key,row in boundary_before.items()}
    index = {}
    for target, context in contexts.items():
        for candidate in context['candidates']:
            key = candidate['kind'],tuple(candidate['key'])
            index.setdefault(key,[]).append(target)
    shared = [dict(kind=kind,key=list(key),targets=sorted(targets),
                   evidence='CONFIGURATION_ONLY',access='NOT_OBSERVED',contention='NOT_INFERRED')
              for (kind,key),targets in sorted(index.items()) if len(targets)>1]
    return dict(schema=SCHEMA,roots=contexts,shared_candidates=shared,
                limits=['endpoint agreement cannot exclude intervening changes',
                        'private directories may share a filesystem backend, not directory locks',
                        'overlay/layer filesystems are not resolved to lower devices',
                        'namespace interface names do not identify shared NIC queues'])
