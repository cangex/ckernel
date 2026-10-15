# SPDX-License-Identifier: GPL-2.0
"""Small, strict correctness/boundary summary; never invent formal acceptance."""
import argparse
import csv
import json
from collections import Counter
from statistics import mean
from pathlib import Path
from template import validate_geometry


def analyze(bundle):
    if Counter((r['condition'],r['n']) for r in bundle['states'])!={ (c,1):3 for c in 'SGFB'}:
        raise ValueError('complete 12-state solo admission required')
    rows=[]
    for result in bundle['states']:
        if result['status']!='PASS' or result['business']['status']!='PASS':raise ValueError('failed state retained; no acceptance')
        window=result['cost_window'];instances=result['business']['instances']
        if any(x['official_grade']!='PASS' or x['exit_code']!=0 for x in instances):raise ValueError('correctness failure')
        end=max(x['end_ns'] for x in instances);start=min(x['start_ns'] for x in instances)
        if not window['before_end_ns']<=start<=end<=window['completion_ack_ns']<=window['end_snapshot_begin_ns']<=window['end_snapshot_end_ns']<=result['grading_begin_ns']:
            raise ValueError('cost/grading boundary mismatch')
        for instance in instances:
            rows.append(dict(condition=result['condition'],n=result['n'],slot=instance['slot'],
                business_s=instance['elapsed_s'],prepare_s=(result['setup_end_ns']-result['request_ns'])/1e9,
                request_to_business_end_s=(instance['end_ns']-result['request_ns'])/1e9,
                observed_turnover_s=(result['turnover_end_ns']-result['request_ns'])/1e9,
                scoring_and_retention_s=(result['grading_end_ns']-result['grading_begin_ns'])/1e9,
                cleanup_s=(result['turnover_end_ns']-result['retention_and_cleanup_begin_ns'])/1e9,
                end_snapshot_lag_ms=(window['end_snapshot_begin_ns']-end)/1e6,official='PASS'))
    checked=[]
    objects={o['id']:o for o in bundle['objects']}
    for op in bundle['geometry_observations']:
        checked.append(validate_geometry(op['observed'],objects[op['identity']]['spec']))
    expected={o['id'] for o in bundle['objects']}
    seen={op['identity'] for op in bundle['geometry_observations']}
    if expected-seen:raise ValueError('missing actual geometry')
    ids=[o['thin_id'] for o in bundle['objects']]
    if len(ids)!=len(set(ids)):raise ValueError('thin identity reused')
    if any(o['state']!='DELETED' for o in bundle['objects']):raise ValueError('final branch not reclaimed')
    groups={arm:{key:mean(r[key] for r in rows if r['condition']==arm)
        for key in ('business_s','prepare_s','observed_turnover_s','cleanup_s','end_snapshot_lag_ms')}
        for arm in 'SGFB'}
    return dict(status='PASS' if bundle['summary']['status']=='PASS' else 'INCOMPLETE',copies=len(rows),rows=rows,solo_admission_means=groups,
        actual_geometry_checks=len(checked),no_thin_id_reuse=True,
        timing='completion-ack boundaries verified; publication/observer lag remains included',
        interference_rate='NOT_AVAILABLE: no loaded comparison',net_benefit='NOT_ESTABLISHED',
        vm_fault_acceptance='NOT_RUN',formal='NOT_RUN')


def main():
    p=argparse.ArgumentParser();p.add_argument('bundle');p.add_argument('output');a=p.parse_args()
    result=analyze(json.loads(Path(a.bundle).read_text().splitlines()[0]))
    out=Path(a.output)
    with out.with_suffix('.json').open('x') as stream:json.dump(result,stream,indent=2)
    with out.with_suffix('.csv').open('x',newline='') as stream:
        if result['rows']:
            w=csv.DictWriter(stream,fieldnames=list(result['rows'][0]));w.writeheader();w.writerows(result['rows'])
    print(json.dumps({k:v for k,v in result.items() if k!='rows'}))


if __name__=='__main__':main()
