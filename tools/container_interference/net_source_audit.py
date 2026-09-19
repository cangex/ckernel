# SPDX-License-Identifier: GPL-2.0
FIELDS={'entries','eligible','selected','releases','skipped'}
TX_FIELDS={'tx_entries','tx_selected','tx_callbacks','tx_callback_ns','tx_callback_max_ns'}
TX_CONTEXT_FIELDS={'tx_irq_skipped','tx_nested_skipped'}


def parse(text):
    if len(text)>1<<20: raise ValueError('source audit size')
    lines=text.splitlines()
    if not lines: raise ValueError('source audit empty')
    header=dict(p.split('=',1) for p in lines[0].split())
    v=header.get('version')
    expected={'version','active','release_active','shift','source_counter_bytes_per_cpu','snapshot'}
    if v in ('2','3'): expected.add('tx_active')
    if (set(header)!=expected or v not in ('1','2','3') or header['snapshot']!='non_atomic'):
        raise ValueError('source audit schema')
    for key in ('active','release_active','shift','source_counter_bytes_per_cpu'): header[key]=int(header[key])
    if v in ('2','3'):
        header['tx_active']=int(header['tx_active'])
        if header['tx_active'] not in (0,1): raise ValueError('TX source state')
    if (header['active'] not in (0,1) or header['release_active'] not in (0,1)
            or not 0<=header['shift']<=16 or header['source_counter_bytes_per_cpu']<=0): raise ValueError('source state')
    cpus={}
    for line in lines[1:]:
        row={k:int(v) for k,v in (p.split('=',1) for p in line.split())}
        if set(row)!=FIELDS|{'cpu'}|(TX_FIELDS if v in ('2','3') else set())|(TX_CONTEXT_FIELDS if v=='3' else set()) or min(row.values())<0: raise ValueError('source row')
        cpu=row.pop('cpu')
        if cpu in cpus or cpu>=4096: raise ValueError('source CPU')
        cpus[cpu]=row
    if not cpus: raise ValueError('no source CPUs')
    return header,cpus


def delta(before,after,shift=0):
    a,ac=parse(before['source_audit']); b,bc=parse(after['source_audit'])
    if (a!=b or ac.keys()!=bc.keys() or before['time_ns']>after['time_ns'] or a['active'] or
            a['release_active'] or a.get('tx_active',0) or a['shift']!=shift): raise ValueError('source boundary')
    totals={k:0 for k in FIELDS|(TX_FIELDS if a['version'] in ('2','3') else set())|
            (TX_CONTEXT_FIELDS if a['version']=='3' else set())}
    for cpu in ac:
        for key in totals:
            diff=bc[cpu][key]-ac[cpu][key]
            if diff<0: raise ValueError('source counter reset')
            if key=='tx_callback_max_ns': totals[key]=max(totals[key],bc[cpu][key])
            else: totals[key]+=diff
    if not totals['entries']>=totals['eligible']>=totals['selected']: raise ValueError('source order')
    if a['version'] in ('2','3') and totals['tx_selected']>totals['tx_entries']: raise ValueError('TX source order')
    if a['version']=='3' and totals['tx_irq_skipped']+totals['tx_nested_skipped']>totals['skipped']:
        raise ValueError('TX skipped context audit')
    high_water=totals.pop('tx_callback_max_ns',None)
    return dict(totals=totals,tx_callback_boot_max_ns=high_water,counter_bytes=a['source_counter_bytes_per_cpu']*len(ac),
                callback_max_scope='boot high water, not window maximum',
                callback_ns_scope='TX callback body only; wrappers, filters, release and IRQ cost not fully separated',
                total_cost='UNKNOWN',scope='all source TCP entries and skb releases, not only target containers')
