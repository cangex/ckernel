#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Replay memory-pressure positives/negatives without inventing page owners."""
import argparse
import hashlib
import json
from pathlib import Path

from collector_audit import audit
from collector_manifest import validate_record_inventory
from counter_mem_check import counts
from explain import explain
from owner_report import fields
from session_check import extract
from source_switches import validate
from y2_memory_check import SOURCE_KEYS


def source_bound(record,source):
    return all(k in record and k in source and record[k]==source[k] for k in SOURCE_KEYS)


def pressure(before,after):
    if len(before)!=6 or len(after)!=6: raise ValueError('group_capacity')
    result=[]
    for a,b in zip(before,after):
        if any(a[k]!=b[k] for k in ('path','cgroup_id','memory.high')):
            raise ValueError('group_identity_or_limit_changed')
        x,y=[counts(r['memory.events.local']) for r in (a,b)]
        if x.keys()!=y.keys() or any(y[k]<x[k] for k in x): raise ValueError('counter_reset')
        delta={k:y[k]-x[k] for k in x}
        result.append(dict(path=a['path'],cgroup_id=a['cgroup_id'],memory_high=a['memory.high'].strip(),
                           local_events=delta,evidence='E1-counter',reclaim_target='UNKNOWN',blocking_container=None))
    return result


def verify(serial,output):
    if serial.stat().st_size>128<<20: raise ValueError('serial capacity')
    raw=serial.read_bytes(); text=raw.decode(); files=extract(text); prefix='/tmp/y2-reclaim-evidence/'
    def value(name): return json.JSONDecoder().raw_decode(files[prefix+name].lstrip())[0]
    output.mkdir(mode=0o700)
    plan,result,permit=[value(n+'.json') for n in ('plan','result','permit')]
    errors=[]; states=[]
    if 'CIS_PROFILE_VM_EXIT=0' not in text.splitlines(): errors.append('guest_exit')
    if any(s in text for s in ('page_counter underflow:', 'BUG: KASAN:', 'Oops:', 'Kernel panic','WARNING: CPU:')):
        errors.append('kernel_warning')
    expected_cases=[dict(name='common',actors=[0,1],parent_high=96<<20,private_high=None),
                    dict(name='separate',actors=[0,2],parent_high=96<<20,private_high=None),
                    dict(name='private',actors=[0,2],parent_high=None,private_high=16<<20)]
    expected_order=[dict(case=c,round=r,enabled=v,label='%s%d%s'%(c['name'],r,'on' if v else 'off'))
        for r in range(3) for c in expected_cases for v in ((False,True) if r%2==0 else (True,False))]
    if (plan['schema']!='cis-y2-reclaim-plan-v1' or plan['cases']!=expected_cases or plan['order']!=expected_order or
            plan['window_ms']!=2000 or plan['workload_seconds']!=3 or plan['bytes_per_allocation']!=64<<20 or
            plan['cpus']!=[0,1] or plan['mems']!=[0]): errors.append('plan')
    if [s['label'] for s in result['states']]!=[s['label'] for s in expected_order]: errors.append('state_order')
    if any(result['source'].get(k)!=permit['source'].get(k) for k in SOURCE_KEYS): errors.append('source_binding')
    records=[json.JSONDecoder().raw_decode(v.lstrip())[0] for k,v in files.items()
             if k.startswith(prefix+'records/') and k.endswith('.json')]
    records=[r for r in records if 'session_id' in r]
    if len(records)!=9: errors.append('capture_count')
    for expected in expected_order:
        label=expected['label']; ev=value(label+'-evidence.json'); c=expected['case']
        if any(ev.get(k)!=v for k,v in expected.items()): errors.append('plan_state_'+label)
        if ev['exit_codes']!=[0,0] or ev['release_ns'][0]<ev['window']['end_ns']: errors.append('run_boundary_'+label)
        if ev['captured']['end_ns']>ev['release_ns'][0]: errors.append('premature_release_'+label)
        events=pressure(ev['before']['groups'],ev['captured']['groups'])
        if any(d['local_events'].get(k,0) for d in events for k in ('oom','oom_kill','max')): errors.append('memory_failure_'+label)
        high=[d['local_events'].get('high',0) for d in events]
        if c['name']=='common' and (not high[0] or any(high[1:])): errors.append('common_pressure_truth_'+label)
        if c['name']=='separate' and any(high): errors.append('separate_pressure_truth_'+label)
        if c['name']=='private' and (not high[2] or any(v for i,v in enumerate(high) if i!=2)): errors.append('private_pressure_truth_'+label)
        workloads=[]
        for job in ev['jobs']:
            log=files[prefix+job['log']]
            rows=[fields(line) for line in log.splitlines() if line.startswith('CIS_RECLAIM_RESULT ')]
            if len(rows)!=1 or rows[0].get('allocations',0)<=0 or rows[0].get('bytes_each')!=64<<20:
                errors.append('business_completion_'+label); continue
            d=rows[0]
            if not ev['window']['start_ns']<d['start_ns']<ev['window']['end_ns']<d['end_ns']:
                errors.append('business_window_'+label)
            workloads.append(dict(actor=job['actor'],**d))
        entry=dict(label=label,enabled=ev['enabled'],case=c['name'],round=ev['round'],pressure=events,workloads=workloads)
        if ev['enabled']:
            record=next(r for r in records if r['session_id']==ev['session_id'])
            if not source_bound(record,plan['source']): errors.append('capture_source_'+label)
            if record['window']!=ev['window']: errors.append('capture_window_'+label)
            validate_record_inventory(record)
            capture=files[prefix+'records/'+str(ev['session_id'])+'.jsonl'].encode()
            report=explain(record,capture,finding_limit=4096); scope=audit(record,capture)
            if report['quality']['status']!='PASS' or scope['status']!='PASS': errors.append('capture_'+label)
            observations=report['findings']; actual=set()
            identities=[record['root_identities'][ev['targets'][i]] for i in c['actors']]
            known={(v['id'],v['generation']) for v in identities}
            for finding in observations:
                if finding['kind']!='observed_interval' or finding.get('observation') not in ('memcg_reclaim_interval','direct_reclaim_interval'):
                    errors.append('unexpected_finding_'+label); continue
                actor=(finding['id'],finding['generation']); actual.add(actor)
                if actor not in known or finding.get('owner')!='unknown' or finding.get('causal') is not False:
                    errors.append('invented_reclaim_owner_'+label)
            if c['name']=='common' and not actual: errors.append('common_reclaim_missing_'+label)
            if c['name']=='separate' and actual: errors.append('separate_reclaim_false_positive_'+label)
            if c['name']=='private' and actual!={(identities[0]['id'],identities[0]['generation'])}:
                errors.append('private_reclaim_misattribution_'+label)
            validate(ev['active_sources'],'reclaim',record['requested_ns'],record['window']['end_ns'])
            entry.update(observed_actors=[list(a) for a in sorted(actual)],findings=report['finding_count'],unknown=report['unknown_count'],
                process_capturing_cpu_ns=record['process_cpu_budget']['phase_peak_cpu_ns']['CAPTURING'],
                combined_process_rss_peak_bytes=record['combined_rss_peak_bytes'],quality=report['quality'])
            for suffix,obj in (('record',record),('report',report),('scope',scope)):
                (output/(label+'.'+suffix+'.json')).write_text(json.dumps(obj,indent=2))
            (output/(label+'.jsonl')).write_bytes(capture)
        else: validate(ev['active_sources'],None,ev['window']['start_ns'],ev['window']['end_ns'])
        validate(ev['idle_sources'],None,ev['window']['start_ns'],2**64-1)
        states.append(entry)
    summary=dict(schema='cis-y2-reclaim-check-v1',status='PASS_SCOPED' if not errors else 'FAIL',
        errors=sorted(set(errors)),serial_sha256=hashlib.sha256(raw).hexdigest(),states=states,
        analysis_source_sha256={name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                                for name in ('y2_reclaim_check.py','explain.py','collector_audit.py','source_switches.py')},
        limits=['private anonymous memory and induced ancestor/own high pressure in a VM',
                'native tracepoints do not expose reclaimed-page owner or actual target memcg',
                'configuration and local high counters must not be substituted for a native reclaim-resource identity',
                'global direct reclaim/kswapd/compaction and unique blocking tenant are not certified',
                'whole workload spans capture and drain; throughput is not a same-window performance acceptance'])
    (output/'verification.json').write_text(json.dumps(summary,indent=2))
    return summary


if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('serial',type=Path); parser.add_argument('output',type=Path)
    args=parser.parse_args(); report=verify(args.serial,args.output)
    print(json.dumps(dict(status=report['status'],errors=report['errors'],states=len(report['states']))))
    raise SystemExit(report['status']!='PASS_SCOPED')
