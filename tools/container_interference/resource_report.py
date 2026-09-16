#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Extract whole-window observer charge and CPU snapshots without inventing owners."""
import argparse
import json
import pathlib
import re

FIELDS=re.compile(r'(\w+)=([^ ;]+)')


def analyze(text):
    runs, current, collecting, body=[],None,None,[]
    rss, process_cpu=[],[]
    for line in text.splitlines():
        if line.startswith('CIS_FLEET_BEGIN '):
            current={'configuration':dict(FIELDS.findall(line)),'snapshots':{}}
            runs.append(current)
        elif current is not None and line.startswith('CIS_SNAPSHOT '):
            _,phase,path=line.split(' ',2);collecting=(phase,path);body=[]
        elif current is not None and line=='CIS_SNAPSHOT_END':
            if collecting:
                phase,path=collecting
                current['snapshots'].setdefault(phase,{})[path]='\n'.join(body)
            collecting=None
        elif collecting:
            body.append(line)
        elif line.startswith('{'):
            try:r=json.loads(line)
            except ValueError:continue
            if r.get('kind')=='budget':
                f=dict(FIELDS.findall(r['detail']))
                rss.append(int(f.get('rss_bytes',0)));process_cpu.append(int(f.get('user_cpu_ns',0)))
    out=[]
    for run in runs:
        config=run['configuration'];s=run['snapshots'].get('start',{});e=run['snapshots'].get('end',{})
        entry={'configuration':config}
        cpu='/sys/fs/cgroup/cis-monitor/cpu.stat'
        memory='/sys/fs/cgroup/cis-monitor/memory.current'
        if cpu in s and cpu in e:
            before=dict(x.split() for x in s[cpu].splitlines());after=dict(x.split() for x in e[cpu].splitlines())
            entry['observer_cgroup_cpu_usec']={k:int(after[k])-int(before[k]) for k in ('usage_usec','user_usec','system_usec') if k in before and k in after}
        if memory in s and memory in e:
            entry['observer_memory_current_start_bytes']=int(s[memory]);entry['observer_memory_current_end_bytes']=int(e[memory])
        if '/proc/stat' in s and '/proc/stat' in e:
            def counters(v):
                return {row[0]:list(map(int,row[1:9])) for line in v.splitlines() if (row:=line.split()) and re.fullmatch(r'cpu\d+',row[0])}
            a,b=counters(s['/proc/stat']),counters(e['/proc/stat'])
            cpu_rows=[]
            for name in a.keys()&b.keys():
                delta=[y-x for x,y in zip(a[name],b[name])];total=sum(delta)
                cpu_rows.append({'cpu':name,'delta_user_hz_ticks':delta,'busy_fraction':(total-delta[3]-delta[4]-delta[7])/total if total>0 else None})
            entry['per_cpu']=sorted(cpu_rows,key=lambda x:int(x['cpu'][3:]))
            entry['management_cpu']=next((x for x in cpu_rows if x['cpu']=='cpu0'),None)
            entry['busiest_cpu']=max(cpu_rows,key=lambda x:x['busy_fraction'] or 0) if cpu_rows else None
        out.append(entry)
    return {'version':1,'runs':out,'max_observer_rss_bytes':max(rss,default=None),
            'max_reported_process_cpu_ns':max(process_cpu,default=None),
            'limitations':['RSS is not total kernel memory; memory.current is charge, not ownership of every shared page.',
                           'Startup and unregister CPU outside snapshots require separate budget records.',
                           'Per-CPU kernel work is not automatically attributed to the observer; retain unknown background cost.',
                           'Requested duration differs from actual final allocation completion in reclaim scenarios.']}


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('log',type=pathlib.Path);p.add_argument('output',type=pathlib.Path)
    a=p.parse_args();r=analyze(a.log.read_text())
    with a.output.open('x') as f:json.dump(r,f,indent=2);f.write('\n')
    print(json.dumps({'runs':len(r['runs']),'max_observer_rss_bytes':r['max_observer_rss_bytes']},indent=2))
