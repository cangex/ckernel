# SPDX-License-Identifier: GPL-2.0
"""All-entry audit, including source-filter work not delivered to BPF."""
FIELDS={'entries','eligible','sampled','steps','capped','irq_filtered'}
FREE_FIELDS={'free_entries','free_items','free_capped'}
CONTEXT_FIELDS={'free_nested','free_nmi','free_irq'}


def parse(text):
    lines=text.splitlines()
    if not lines or len(text)>1<<20: raise ValueError('source audit size')
    h=dict(p.split('=',1) for p in lines[0].split())
    extended=h.get('version') in ('2','3'); levels=h.get('version')=='3'
    if (set(h)!=({'version','active','shift','cache','snapshot','bytes_per_cpu'} | ({'release_active'} if extended else set()) | ({'guard_bytes_per_cpu'} if levels else set())) or
            h['version'] not in ('1','2','3') or h['snapshot']!='non_atomic' or not h['cache'] or len(h['cache'])>=64):
        raise ValueError('source audit schema')
    for k in ('active','shift','bytes_per_cpu'): h[k]=int(h[k])
    if levels:
        h['guard_bytes_per_cpu']=int(h['guard_bytes_per_cpu'])
        if not 3<=h['guard_bytes_per_cpu']<=64: raise ValueError('context guard size')
    if extended:
        h['release_active']=int(h['release_active'])
        if h['release_active'] not in (0,1): raise ValueError('release state')
    if h['active'] not in (0,1) or not 0<=h['shift']<=16 or h['bytes_per_cpu']<=0:
        raise ValueError('source state')
    cpus={}
    for line in lines[1:]:
        row={k:int(v) for k,v in (p.split('=',1) for p in line.split())}
        if set(row)!=(FIELDS|{'cpu'}|(FREE_FIELDS if extended else set())|(CONTEXT_FIELDS if levels else set())) or min(row.values())<0: raise ValueError('source row')
        cpu=row.pop('cpu')
        if cpu in cpus or cpu>=4096: raise ValueError('source CPU set')
        cpus[cpu]=row
    if not cpus: raise ValueError('missing source CPUs')
    return h,cpus


def delta(before,after,shift=6,cache='maple_node'):
    ha,a=parse(before['source_audit']); hb,b=parse(after['source_audit'])
    if (before['time_ns']>after['time_ns'] or a.keys()!=b.keys() or
            ha!=hb or ha['active'] or ha.get('release_active',0) or ha['shift']!=shift or ha['cache']!=cache):
        raise ValueError('source boundary or configuration')
    fields=FIELDS | (FREE_FIELDS if ha['version'] in ('2','3') else set()) | (CONTEXT_FIELDS if ha['version']=='3' else set())
    totals={k:0 for k in fields}
    for cpu in a:
        for key in fields:
            n=b[cpu][key]-a[cpu][key]
            if n<0: raise ValueError('source counter reset/wrap')
            totals[key]+=n
    if (totals['entries']<totals['eligible']+totals['irq_filtered'] or
            totals['eligible']<totals['sampled'] or totals['steps']<totals['sampled']):
        raise ValueError('inconsistent source counters')
    return dict(totals=totals,declared_counter_bytes=ha['bytes_per_cpu']*len(a),
                declared_guard_bytes=ha.get('guard_bytes_per_cpu',0)*len(a),
                possible_cpus=len(a),snapshot='non_atomic',scope='all source entries, not target-only or total cost')
