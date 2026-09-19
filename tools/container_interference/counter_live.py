# SPDX-License-Identifier: GPL-2.0
"""Verify terminal per-CPU aggregates against the independent event stream."""
from collections import defaultdict
import json

from owner_report import fields
from explain import within_window


def analyze(record, raw, quality):
    selected = record.get('selected_objects', [])
    if not selected:
        return dict(status='NOT_REQUESTED', objects=[], shared_objects=[])
    if (not isinstance(selected,list) or not 1<=len(selected)<=8 or len(set(selected))!=len(selected)
            or any(type(a) is not int or not 0<a<2**64 or a%8 for a in selected)):
        raise ValueError('counter selection capacity')
    rows=[json.loads(line) for line in raw.decode().splitlines()]
    known={(v['id'],v['generation']) for v in record['root_identities'].values()}
    declarations=[fields(r.get('detail','')) for r in rows if r.get('kind')=='counter_selection']
    expected=[dict(index=i,count=len(selected),object=a,readback=1) for i,a in enumerate(selected)]
    defects=[]
    if declarations!=expected: defects.append('selection_readback')
    audit=[fields(r.get('detail','')) for r in rows if r.get('kind')=='counter_sum_audit']
    if (len(audit)!=1 or audit[0].get('objects')!=len(selected) or
            audit[0].get('buckets')!=len(selected)*12 or audit[0].get('producers_detached')!=1 or
            not 1<=audit[0].get('targets',0)<=2 or not 1<=audit[0].get('possible_cpus',0)<=512):
        defects.append('terminal_audit')
    observed=defaultdict(list); summaries={}
    for row in rows:
        d=fields(row.get('detail','')); kind=row.get('kind')
        if kind=='COUNTER' and d.get('object') in selected and 2<=d.get('stage',0)<=8:
            required={'object_generation','operation','call_ns','sample_time_ns','sample_shift','pages','depth'}
            if (not required<=d.keys() or (row.get('id'),row.get('generation')) not in known or
                    not 1<=d['operation']<=6 or not 0<=d['object_generation']<2**63 or
                    not 0<=d['sample_shift']<=16 or not 0<=d['depth']<64 or not 0<=d['pages']<2**64 or
                    not within_window(record,d['call_ns'],d['sample_time_ns'])):
                defects.append('sample_identity_or_window'); continue
            observed[d['object'],row['id'],row['generation'],d['operation']].append(d)
        if kind!='counter_sum': continue
        required={'protocol','object','object_generation','operation','first_ns','last_ns','sample_shift',
                  'tainted','min_depth','max_depth','producers_detached'} | {
                  k+str(i) for k in ('n','q') for i in range(2,9)} | {'h'+str(i) for i in range(8)}
        if not required<=d.keys() or any(d[k]<0 for k in required):
            defects.append('summary_schema'); continue
        key=d['object'],row.get('id'),row.get('generation'),d['operation']
        if (key in summaries or key[0] not in selected or key[1:3] not in known or
                not 1<=d['operation']<=6 or d['protocol']!=1 or d['producers_detached']!=1 or
                d['tainted'] not in (0,1) or not 0<=d['sample_shift']<=16):
            defects.append('summary_identity'); continue
        summaries[key]=d
    if summaries.keys()!=observed.keys(): defects.append('summary_population')
    result=[]; participants=defaultdict(set)
    for key, d in summaries.items():
        samples=observed.get(key,[])
        if not samples: continue
        counts={i:sum(s['stage']==i for s in samples) for i in range(2,9)}
        pages={i:sum(s['pages'] for s in samples if s['stage']==i) for i in range(2,9)}
        hist=[0]*8
        for s in samples:
            offset=s['sample_time_ns']-s['call_ns']
            hist[sum(offset >= (1000 << (2*i)) for i in range(7))]+=1
        if (any(d['n'+str(i)]!=counts[i] or d['q'+str(i)]!=pages[i] for i in range(2,9)) or
                any(d['h'+str(i)]!=hist[i] for i in range(8)) or
                d['first_ns']!=min(s['sample_time_ns'] for s in samples) or
                d['last_ns']!=max(s['sample_time_ns'] for s in samples) or
                d['min_depth']!=min(s['depth'] for s in samples) or
                d['max_depth']!=max(s['depth'] for s in samples)):
            defects.append('summary_event_mismatch')
        generations={s.get('object_generation',0) for s in samples}
        shifts={s['sample_shift'] for s in samples}
        eligible=(not d['tainted'] and generations=={d['object_generation']} and
                  d['object_generation']>0 and shifts=={d['sample_shift']})
        if not d['tainted'] and not eligible: defects.append('missing_generation_downgrade')
        row=dict(address=key[0],container=list(key[1:3]),operation=key[3],
                 generation=d['object_generation'] if eligible else None,
                 update_counts=counts,native_quantities=pages,entry_to_step_hist=hist,
                 interval_ns=[d['first_ns'],d['last_ns']],sample_shift=d['sample_shift'],
                 min_depth=d['min_depth'],max_depth=d['max_depth'],
                 evidence='E2' if eligible else 'E1',holder=None)
        result.append(row)
        if eligible:
            for stage,count in counts.items():
                if count: participants[key[0],d['object_generation'],stage].add(key[1:3])
    accepted=quality.get('status')=='PASS' and not defects
    if not accepted:
        for row in result: row['evidence']='UNACCEPTED'
    return dict(status='PASS' if accepted else 'FAIL',defects=sorted(set(defects)),objects=result,
                shared_objects=[dict(address=a,generation=g,stage=s,containers=[list(v) for v in sorted(actors)],
                                     relation='shared_counter_updates',evidence='E2',holder=None)
                                for (a,g,s),actors in sorted(participants.items()) if len(actors)>1] if accepted else [],
                count_scope='observed sampled update stages, not extrapolated population; incomplete calls may contribute',
                histogram_lower_bounds_ns=[0]+[1000 << (2*i) for i in range(7)],
                time_scope='call-entry to each update event; not atomic latency or total service cost',
                source_sampling='unchanged per-CPU call sampler, not full selected-object instrumentation',
                cacheline_contention='UNVERIFIED',causal='NOT_CLAIMED')
