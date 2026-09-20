#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Live identity/configuration negatives in a disposable container guest."""
import json
import os
from pathlib import Path
import subprocess
import time

import resource_topology as topology
from source_switches import observe


def run():
    if not Path('/cis-disposable-vm').is_file() or os.geteuid():
        raise PermissionError('isolated VM only')
    out=Path('/tmp/topology-evidence');out.mkdir(mode=0o700)
    cg=Path('/sys/fs/cgroup/cis-topology');cg.mkdir()
    paths=[cg/'a',cg/'b']
    children=[];fds=[];logs=[];snapshots={};checks={}

    def take(name,root):
        row=topology.collect(root);snapshots[name]=row
        if row['status']!='OBSERVED_ENDPOINT':raise ValueError((name,row))
        return row

    def wait_path(path):
        end=time.monotonic()+5
        while not path.exists():
            if time.monotonic()>end:raise TimeoutError(str(path))
            time.sleep(.01)

    try:
        before_sources=observe(None)
        roots=[];pids=[]
        for i,path in enumerate(paths):
            path.mkdir();fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY);fds.append(fd)
            roots.append(dict(fd=fd,path=str(path),id=os.fstat(fd).st_ino,generation=i+1))
            log=(out/('actor%d.log'%i)).open('x');logs.append(log)
            child=subprocess.Popen(['/session_launch',str(path),str(i),'/topology_workload','unused'],
                                   stdout=log,stderr=log);children.append(child)
            deadline=time.monotonic()+5
            while not (path/'cgroup.procs').read_text().strip():
                if time.monotonic()>deadline:raise TimeoutError('container PID')
                time.sleep(.01)
            pid=int((path/'cgroup.procs').read_text().strip())
            pids.append(pid);wait_path(Path('/proc')/str(pid)/'root/tmp/topology-ready')
        a=take('a0',roots[0]);b=take('b0',roots[1])
        a1=take('a1',roots[0]);b1=take('b1',roots[1])
        report=topology.compare_roots({'a':dict(topology=a),'b':dict(topology=b)},
                                      {'a':dict(topology=a1),'b':dict(topology=b1)})
        checks['same_ancestor_is_configuration_only']=bool(report['shared_candidates']) and all(
            r['evidence']=='CONFIGURATION_ONLY' and r['contention']=='NOT_INFERRED'
            for r in report['shared_candidates'])
        def tmp_device(row):
            return {m['device'] for t in row['tasks'] for m in t['mounts'] if m['mountpoint']=='/tmp'}
        checks['private_tmpfs_not_same_backend']=bool(tmp_device(a)) and tmp_device(a).isdisjoint(tmp_device(b))
        checks['loopback_names_do_not_join_networks']=(a['tasks'][0]['interfaces']==['lo'] and
            b['tasks'][0]['interfaces']==['lo'] and a['tasks'][0]['namespaces']['net']!=b['tasks'][0]['namespaces']['net'] and
            not any(r['kind'].startswith('net') for r in report['shared_candidates']))
        os.sched_setaffinity(pids[0],{2})
        moved=take('affinity',roots[0])
        checks['affinity_invalidates']=topology.stable(a,moved)['status']=='CHANGED_INVALIDATED'
        child_cg=paths[0]/'child';child_cg.mkdir()
        (child_cg/'cgroup.procs').write_text(str(pids[0]))
        child_view=take('child',roots[0])
        checks['descendant_migration_invalidates']=(topology.stable(moved,child_view)['status']=='CHANGED_INVALIDATED' and
            len(child_view['tasks'])==1 and child_view['coverage']['cgroups']==2)
        control=Path('/proc')/str(pids[0])/'root/tmp'
        (control/'topology-command').write_text('namespace');wait_path(control/'topology-ack')
        ns=take('namespace',roots[0])
        checks['namespace_change_invalidates']=topology.stable(child_view,ns)['status']=='CHANGED_INVALIDATED'
        restarted=dict(roots[0],generation=50)
        reg=take('reregistered',restarted)
        checks['registration_generation_invalidates']=topology.stable(ns,reg)['status']=='CHANGED_INVALIDATED'
        for pid in pids:
            (Path('/proc')/str(pid)/'root/tmp/topology-command').write_text('exit')
        codes=[c.wait(timeout=5) for c in children]
        checks['business_exit']=codes==[0,0]
        exited=take('exited',roots[0])
        checks['short_lived_task_not_retained']=not exited['tasks'] and topology.stable(reg,exited)['status']=='CHANGED_INVALIDATED'
        child_cg.rmdir();paths[0].rmdir()
        deleted=topology.collect(roots[0]);snapshots['deleted']=deleted
        checks['deleted_root_is_unknown']=deleted['status']=='IDENTITY_UNKNOWN'
        paths[0].mkdir();fd=os.open(paths[0],os.O_RDONLY|os.O_DIRECTORY);fds.append(fd)
        recreated=take('recreated',dict(fd=fd,path=str(paths[0]),id=os.fstat(fd).st_ino,generation=51))
        checks['same_path_recreated_not_same_registration']=topology.stable(exited,recreated)['status']=='CHANGED_INVALIDATED'
        (out/'snapshots.json').write_text(json.dumps(snapshots,indent=2))
        (out/'shared.json').write_text(json.dumps(report,indent=2))
        after_sources=observe(None)
        (out/'result.json').write_text(json.dumps(dict(schema='cis-y1-topology-runtime-v1',checks=checks,
            before_sources=before_sources,after_sources=after_sources,status='PASS' if all(checks.values()) else 'FAIL'),indent=2))
        if not all(checks.values()):raise ValueError(checks)
    finally:
        for child in children:
            if child.poll() is None:child.terminate();child.wait(timeout=5)
        for fd in fds:os.close(fd)
        for log in logs:log.close()


if __name__=='__main__':run()
