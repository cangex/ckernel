# SPDX-License-Identifier: GPL-2.0
"""Non-atomic source snapshots, distinct from target BPF delivery accounting."""
from pathlib import Path
import time


def parse(text):
    rows=text.splitlines()
    if not rows: raise ValueError('missing counter source audit')
    header=dict(v.split('=',1) for v in rows[0].split())
    if (set(header)!={'version','active','shift','sequence','counter_bytes','source_counter_bytes_per_cpu','snapshot'} or
            header.get('version')!='1' or header.get('snapshot')!='non_atomic'): raise ValueError('audit version')
    for key in ('active','shift','sequence','counter_bytes','source_counter_bytes_per_cpu'):
        header[key]=int(header[key])
    if header['active'] not in (0,1) or not 0<=header['shift']<=16: raise ValueError('audit state')
    cpus={}
    for line in rows[1:]:
        values={k:int(v) for k,v in (part.split('=',1) for part in line.split())}
        if set(values)!={'cpu','entries','eligible','sampled','steps','capped'} or min(values.values())<0:
            raise ValueError('audit row')
        cpu=values.pop('cpu')
        if cpu in cpus: raise ValueError('duplicate cpu')
        cpus[cpu]=values
    if not cpus or len(cpus)>4096: raise ValueError('audit capacity')
    return dict(header=header,cpus=cpus)


def observe():
    before=time.monotonic_ns(); text=Path('/sys/kernel/debug/cis_counter_audit').read_text(); after=time.monotonic_ns()
    parse(text)
    return dict(before_ns=before,after_ns=after,text=text)


def delta(before, after, shift):
    a,b=parse(before['text']),parse(after['text'])
    if (not before['before_ns']<=before['after_ns']<=after['before_ns']<=after['after_ns'] or
            a['cpus'].keys()!=b['cpus'].keys() or
            any(s['header']['active'] or s['header']['shift']!=shift for s in (a,b))):
        raise ValueError('source snapshot boundaries')
    total={key:0 for key in ('entries','eligible','sampled','steps','capped')}
    for cpu in a['cpus']:
        for key in total:
            change=b['cpus'][cpu][key]-a['cpus'][cpu][key]
            if change<0: raise ValueError('source counter reset or wrap')
            total[key]+=change
    if not total['entries']>=total['eligible']>=total['sampled'] or total['steps']<total['sampled']:
        raise ValueError('inconsistent source count snapshot')
    return dict(status='PASS',totals=total,unsupported_or_recursive_entries=total['entries']-total['eligible'],
                sampled_out_calls=total['eligible']-total['sampled'],possible_cpus=len(a['cpus']),
                declared_source_counter_bytes=len(a['cpus'])*b['header']['source_counter_bytes_per_cpu'],
                counter_structure_bytes=b['header']['counter_bytes'],scope='all source contexts, non-atomic; not target-only counts or total CPU/memory',
                complete_cost='UNKNOWN')
