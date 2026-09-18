# SPDX-License-Identifier: GPL-2.0
FIELDS={'entries','eligible','selected','releases','skipped'}


def parse(text):
    if len(text)>1<<20: raise ValueError('source audit size')
    lines=text.splitlines()
    if not lines: raise ValueError('source audit empty')
    header=dict(p.split('=',1) for p in lines[0].split())
    if (set(header)!={'version','active','release_active','shift','source_counter_bytes_per_cpu','snapshot'}
            or header['version']!='1' or header['snapshot']!='non_atomic'):
        raise ValueError('source audit schema')
    for key in ('active','release_active','shift','source_counter_bytes_per_cpu'): header[key]=int(header[key])
    if (header['active'] not in (0,1) or header['release_active'] not in (0,1)
            or not 0<=header['shift']<=16 or header['source_counter_bytes_per_cpu']<=0): raise ValueError('source state')
    cpus={}
    for line in lines[1:]:
        row={k:int(v) for k,v in (p.split('=',1) for p in line.split())}
        if set(row)!=FIELDS|{'cpu'} or min(row.values())<0: raise ValueError('source row')
        cpu=row.pop('cpu')
        if cpu in cpus or cpu>=4096: raise ValueError('source CPU')
        cpus[cpu]=row
    if not cpus: raise ValueError('no source CPUs')
    return header,cpus


def delta(before,after,shift=0):
    a,ac=parse(before['source_audit']); b,bc=parse(after['source_audit'])
    if (a!=b or ac.keys()!=bc.keys() or before['time_ns']>after['time_ns'] or a['active'] or
            a['release_active'] or a['shift']!=shift): raise ValueError('source boundary')
    totals={k:0 for k in FIELDS}
    for cpu in ac:
        for key in FIELDS:
            diff=bc[cpu][key]-ac[cpu][key]
            if diff<0: raise ValueError('source counter reset')
            totals[key]+=diff
    if not totals['entries']>=totals['eligible']>=totals['selected']: raise ValueError('source order')
    return dict(totals=totals,counter_bytes=a['source_counter_bytes_per_cpu']*len(ac),
                total_cost='UNKNOWN',scope='all source TCP entries and skb releases, not only target containers')
