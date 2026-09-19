# SPDX-License-Identifier: GPL-2.0
"""Bounded bookend accounting, not an exclusive observer attribution model."""
import os
from pathlib import Path
import time

PF_KTHREAD = 0x00200000
CGROUP_FILES = ('cpu.stat','memory.current','memory.peak','memory.stat','memory.events')
MEMORY_KB = ('MemAvailable','MemFree','Buffers','Cached','Slab','SReclaimable',
             'SUnreclaim','KernelStack','PageTables','Percpu','VmallocUsed')


def task_stat(text):
    left=text.find('('); right=text.rfind(')')
    if left<1 or right<=left: raise ValueError('task stat delimiters')
    pid=int(text[:left].strip()); words=text[right+1:].split()
    if len(words)<20 or pid<=0: raise ValueError('task stat fields')
    flags,user,system,start=[int(words[i]) for i in (6,11,12,19)]
    if min(flags,user,system,start)<0: raise ValueError('negative task stat')
    return dict(pid=pid,name=text[left+1:right],flags=flags,user_ticks=user,
                system_ticks=system,start_ticks=start)


def kernel_threads(proc=Path('/proc'),limit=4096):
    started=time.monotonic_ns(); rows={}; scanned=0; races=0; capped=False
    with os.scandir(proc) as entries:
        for entry in entries:
            if not entry.name.isascii() or not entry.name.isdigit(): continue
            if scanned==limit: capped=True; break
            scanned+=1
            try:
                with (proc/entry.name/'stat').open() as stream: text=stream.read(16385)
                if len(text)>16384: raise ValueError('task stat size')
                row=task_stat(text)
                if row['pid']!=int(entry.name): raise ValueError('task identity')
            except (OSError,ValueError):
                races+=1; continue
            if row['flags'] & PF_KTHREAD:
                rows['%d:%d'%(row['pid'],row['start_ticks'])]=row
    return dict(start_ns=started,end_ns=time.monotonic_ns(),scanned=scanned,
                limit=limit,capped=capped,races=races,tasks=rows)


def counters(text):
    result={}
    for line in text.splitlines():
        words=line.split()
        if len(words)!=2 or words[0] in result or not words[1].isdigit():
            raise ValueError('counter schema')
        result[words[0]]=int(words[1])
    return result


def counter_delta(a,b):
    a,b=counters(a),counters(b)
    if a.keys()!=b.keys(): raise ValueError('counter keys changed')
    result={k:b[k]-a[k] for k in a}
    if any(v<0 for v in result.values()): raise ValueError('counter regression')
    return result


def cgroup_cost(a,b):
    cpu=counter_delta(a['cpu.stat'],b['cpu.stat'])
    if not {'usage_usec','user_usec','system_usec'}<=cpu.keys():
        raise ValueError('missing cgroup CPU accounting')
    memory=[]; peaks=[]
    for row in (a,b):
        values=[row[k].strip() for k in ('memory.current','memory.peak')]
        if any(not v.isdigit() for v in values): raise ValueError('cgroup memory scalar')
        memory.append(int(values[0])); peaks.append(int(values[1]))
    if peaks[1]<peaks[0]: raise ValueError('unannounced memory peak reset')
    stats=[counters(v['memory.stat']) for v in (a,b)]
    if stats[0].keys()!=stats[1].keys(): raise ValueError('memory stat keys changed')
    return dict(cpu_delta_usec=cpu,memory_current_start_end_bytes=memory,
        cumulative_memory_peak_start_end_bytes=peaks,
        memory_stat_start_end=stats,
        memory_events_delta=counter_delta(a['memory.events'],b['memory.events']))


def meminfo(text):
    result={}
    for line in text.splitlines():
        words=line.split()
        if words and words[0].rstrip(':') in MEMORY_KB:
            if len(words)!=3 or words[2]!='kB' or not words[1].isdigit():
                raise ValueError('meminfo units')
            key=words[0].rstrip(':')
            if key in result: raise ValueError('duplicate meminfo')
            result[key]=int(words[1])*1024
    return result


def analyze(before,after,hz):
    if not isinstance(hz,int) or hz<=0: raise ValueError('clock ticks')
    for row in (before,after):
        if not row['time_ns']<=row['kthreads']['start_ns']<=row['kthreads']['end_ns']<=row['read_end_ns']:
            raise ValueError('cost read boundaries')
    if before['read_end_ns']>=after['time_ns']: raise ValueError('cost snapshots overlap')
    a,b=before['kthreads'],after['kthreads']; threads=[]
    for snap in (a,b):
        if snap['limit']!=4096 or not 0<=snap['scanned']<=4096 or len(snap['tasks'])>snap['scanned']:
            raise ValueError('kthread capacity')
        for key,row in snap['tasks'].items():
            if (key!='%d:%d'%(row['pid'],row['start_ticks']) or not row['flags'] & PF_KTHREAD or
                    min(row['user_ticks'],row['system_ticks'],row['start_ticks'])<0):
                raise ValueError('kthread identity')
    for key in a['tasks'].keys() & b['tasks'].keys():
        old,new=a['tasks'][key],b['tasks'][key]
        user=new['user_ticks']-old['user_ticks']; system=new['system_ticks']-old['system_ticks']
        if min(user,system)<0: raise ValueError('kthread CPU regression')
        threads.append(dict(key=key,name=new['name'],user_ticks=user,system_ticks=system))
    threads.sort(key=lambda row:(-row['system_ticks']-row['user_ticks'],row['key']))
    if len(before['roots'])!=4 or len(after['roots'])!=4: raise ValueError('four business roots required')
    memory=[meminfo(row['memory']) for row in (before,after)]
    if memory[0].keys()!=memory[1].keys(): raise ValueError('meminfo keys changed')
    return dict(schema='cis-x7-cost-v1',scope='sequential benchmark bookends, not capture-only',
        snapshot_read_ns=[row['read_end_ns']-row['time_ns'] for row in (before,after)],
        management=cgroup_cost(before['management'],after['management']),
        actors=[cgroup_cost(a,b) for a,b in zip(before['roots'],after['roots'])],
        kernel_threads=dict(matched=threads,clock_hz=hz,tick_resolution_ns=1e9/hz,
            matched_cpu_ticks=sum(v['user_ticks']+v['system_ticks'] for v in threads),
            new_keys=sorted(b['tasks'].keys()-a['tasks'].keys()),
            gone_keys=sorted(a['tasks'].keys()-b['tasks'].keys()),
            scan_races=[a['races'],b['races']],scan_capped=[a['capped'],b['capped']],
            cpu_exclusive_to_observer=False),
        memory_start_end_bytes=memory,
        memory_delta_bytes={k:memory[1][k]-memory[0][k] for k in memory[0]},
        missing_meminfo=sorted(set(MEMORY_KB)-memory[0].keys()),
        observer_total_cpu_known=False,observer_total_kernel_memory_known=False,
        limits=['management cgroup includes test harness, launch preparation, controller and workers',
                'PF_KTHREAD CPU includes unrelated kernel work; newly born and exited threads are not complete',
                'softirq in business context is not recovered from kernel-thread counters',
                'memory gauges and hierarchical subfields overlap; do not sum them or claim a per-session peak',
                'OFF differences are descriptive, not proof that every delta was caused by the observer',
                'zero CPU tick delta is below accounting resolution, not proof of zero work'])
