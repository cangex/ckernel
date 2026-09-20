# SPDX-License-Identifier: GPL-2.0
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from periodic_plan import digest
import resource_topology as t


def endpoint(id=10,generation=1,device='8:0',pid=22):
    row=dict(schema=t.SCHEMA,id=id,generation=generation,identity_valid=True,
        status='OBSERVED_ENDPOINT',ancestors=[dict(identity=[1,id],path='/cg/'+str(id),
            config={'cpuset.cpus.effective':'0-3','cpuset.mems.effective':'0'}),
            dict(identity=[1,1],path='/cg',config={})],
        tasks=[dict(pid=pid,mounts=[dict(fs='ext4',device=device)])],
        devices=[dict(device=device,diskseq='5',queue_sysfs='/sys/disk/queue')])
    row['fingerprint']=digest({k:row[k] for k in t.FINGERPRINT_FIELDS})
    return row


class TopologyTests(unittest.TestCase):
    def test_mounts_keep_distinct_private_directories_on_shared_backend(self):
        rows=t.parse_mounts('41 3 8:0 /private/a /work rw - ext4 /dev/vda rw\n'
                            '42 3 8:0 /private/b /work\\040two ro - ext4 /dev/vda rw')
        self.assertEqual(rows[1]['mountpoint'],'/work two')
        self.assertNotEqual(rows[0]['root'],rows[1]['root'])
        self.assertEqual(rows[0]['device'],rows[1]['device'])
        self.assertEqual(rows[0]['relation'],'configured_mount_not_access_or_same_inode')

    def test_mount_and_file_capacity_are_not_silent_truncation(self):
        with self.assertRaises(t.Bound):
            t.parse_mounts('\n'.join(['1 0 8:0 / / rw - ext4 x rw']*129))
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'raw';p.write_text('x'*16)
            reader=t.Reader()
            with self.assertRaises(t.Bound): reader.read(p,8)
            self.assertEqual(reader.bytes,9)

    def test_ranges_do_not_expand_per_cpu_storage(self):
        self.assertEqual(t.parse_list('0-1023,2048-4095'),[[0,1023],[2048,4095]])
        for value in ('3-1','2,1','0-2,2-3','9999999','1-2-3','cpu0'):
            with self.assertRaises(ValueError): t.parse_list(value)

    def test_reused_root_task_or_configuration_invalidates(self):
        a=endpoint()
        for b in (endpoint(generation=2),endpoint(device='8:1'),endpoint(pid=23)):
            self.assertEqual(t.stable(a,b)['status'],'CHANGED_INVALIDATED')
        b=copy.deepcopy(a);b['tasks'][0]['pid']=500
        with self.assertRaisesRegex(ValueError,'fingerprint'): t.stable(a,b)

    def test_unknown_does_not_gain_shared_candidate_credit(self):
        self.assertEqual(t.stable(None,None)['status'],'UNOBSERVED')
        a=endpoint();a['status']='PARTIAL'
        a['fingerprint']=digest({k:a[k] for k in t.FINGERPRINT_FIELDS})
        self.assertEqual(t.stable(a,a)['candidates'],[])

    def test_shared_configuration_is_never_a_waiting_relation(self):
        rows={str(i):dict(topology=endpoint(id=i,pid=i+20)) for i in (10,11)}
        report=t.compare_roots(rows,rows)
        kinds={r['kind'] for r in report['shared_candidates']}
        self.assertEqual(kinds,{'block_device','cgroup_ancestor','filesystem_backend'})
        for row in report['shared_candidates']:
            self.assertEqual(row['contention'],'NOT_INFERRED')
            self.assertEqual(row['evidence'],'CONFIGURATION_ONLY')
        other={'10':rows['10'],'11':dict(topology=endpoint(id=11,device='8:1',pid=31))}
        self.assertEqual({r['kind'] for r in t.compare_roots(other,other)['shared_candidates']},
                         {'cgroup_ancestor'})

    def test_time_and_read_budget_stop_before_next_io(self):
        reader=t.Reader(clock=lambda:0)
        reader.clock=lambda:t.LIMITS['wall_ns']+1
        with self.assertRaises(t.Bound): reader.read('/never/open')
        self.assertEqual(reader.reads,0)
        reader=t.Reader();reader.reads=t.LIMITS['reads']
        with self.assertRaises(t.Bound): reader.read('/never/open')

    def test_stat_and_namespace_cgroup_parsers(self):
        self.assertEqual(t.task_start('7 (a name) '+' '.join(['0']*19+['123','0'])),123)
        self.assertEqual(t.cgroup_path('0::/private/a'),'/private/a')
        for v in ('2::/a','0::/a/../b','0::/a\n0::/b'):
            with self.assertRaises(ValueError): t.cgroup_path(v)

    @unittest.skipUnless(Path('/proc/self/fd').is_dir(),'Linux procfs required')
    def test_real_fd_root_walk_is_bounded_and_closes_temporary_fds(self):
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder).resolve();cg=base/'cg';cg.mkdir();root=cg/'a';root.mkdir()
            (root/'cgroup.procs').write_text('')
            (root/'cpu.max').write_text('max 100000')
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            try:
                identity=dict(fd=fd,path=str(root),id=os.fstat(fd).st_ino,generation=2)
                old=len(list(Path('/proc/self/fd').iterdir()))
                for unused in range(3):
                    result=t.collect(identity,cgroup=cg)
                    self.assertEqual(result['status'],'OBSERVED_ENDPOINT')
                    self.assertEqual(len(result['ancestors']),2)
                self.assertEqual(len(list(Path('/proc/self/fd').iterdir())),old)
                identity['generation']=3
                changed=t.collect(identity,cgroup=cg)
                self.assertEqual(t.stable(result,changed)['status'],'CHANGED_INVALIDATED')
                identity['id']+=1
                self.assertEqual(t.collect(identity,cgroup=cg)['status'],'IDENTITY_UNKNOWN')
            finally:os.close(fd)

    def test_task_migration_during_snapshot_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as folder:
            proc=Path(folder);(proc/'20/ns').mkdir(parents=True)
            (proc/'20/ns/mnt').symlink_to('mnt:[1]');(proc/'20/ns/net').symlink_to('net:[2]')
            stat='20 (task) '+' '.join(['0']*19+['123'])
            status='Cpus_allowed_list: 0\nMems_allowed_list: 0'
            values=[stat,'0::/a',status,'1 0 8:0 / / rw - ext4 /dev/vda rw',
                    'head\nhead\nlo: 0',stat,'0::/b',status]
            with patch.object(t.Reader,'read',side_effect=values):
                with self.assertRaisesRegex(ValueError,'moved_or_reused'):
                    t.inspect_task(t.Reader(),20,'/cg/a',proc=proc,cgroup=Path('/cg'))
