#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Replay ordinary-container evidence; no fixture recall or total-cost claim."""
import argparse
import hashlib
import json
from pathlib import Path
import statistics

from session_check import extract
from collector_manifest import validate_inventory
from collector_audit import audit
from counter_report import analyze
from counter_bridge_check import check
from owner_report import fields
from prototype_admission import SOURCE_KEYS
from source_switches import validate

ORDER = ['off0','counter0','counter1','off1','off2','counter2']


def counts(text):
    return {line.split()[0]:int(line.split()[1]) for line in text.splitlines()}


def operations(text, window):
    rows=[fields(line) for line in text.splitlines() if line.startswith('CIS_MEM_OP ')]
    if (len(rows)!=16 or [r.get('index') for r in rows]!=list(range(16)) or
            any(r.get('success')!=1 or r.get('bytes')!=8 << 20 or
                not window['start_ns']<=r.get('begin_ns',0)<r.get('end_ns',0)<=window['end_ns'] for r in rows) or
            any(a['end_ns']>b['begin_ns'] for a,b in zip(rows,rows[1:]))):
        raise ValueError('incomplete or out-of-window memory operation records')
    span=rows[-1]['end_ns']-rows[0]['begin_ns']
    return dict(successful_operations=16,bytes_per_operation=8 << 20,
                first_begin_ns=rows[0]['begin_ns'],last_end_ns=rows[-1]['end_ns'],
                operation_wall_ns=[r['end_ns']-r['begin_ns'] for r in rows],
                complete_loop_span_ns=span,operations_per_second=16e9/span,
                quantile_caveat='16 operations per actor: retain all latencies, no reliable response P99 claim')


def verify(serial, output):
    if serial.stat().st_size>128<<20: raise ValueError('serial capacity')
    data=serial.read_bytes(); text=data.decode(); files=extract(text); prefix='/tmp/counter-mem-evidence/'
    def value(name): return json.JSONDecoder().raw_decode(files[prefix+name].lstrip())[0]
    output.mkdir(mode=0o700)
    plan,result,permit=[value(name+'.json') for name in ('plan','result','permit')]
    errors=[]; states=[]
    if 'CIS_PROFILE_VM_EXIT=0' not in text.splitlines(): errors.append('guest_exit')
    if any(s in text for s in ('page_counter underflow:', 'BUG: KASAN:', 'Oops:', 'Kernel panic', 'WARNING: CPU:')):
        errors.append('kernel_warning_or_failure')
    if (plan.get('order')!=ORDER or plan.get('operations')!=16 or plan.get('bytes_per_operation')!=8 << 20 or
            plan.get('sample_shift')!=6 or plan.get('memory_max_bytes')!=64 << 20 or
            plan.get('roots')!=2 or plan.get('cpu')!=[0,1] or plan.get('management_cpu')!=7):
        errors.append('frozen_plan')
    if any(result['source'].get(k)!=permit['source'].get(k) for k in SOURCE_KEYS): errors.append('source_binding')
    if [s['label'] for s in result['states']]!=ORDER: errors.append('state_order')
    record_paths=[p for p in files if p.startswith(prefix+'records/') and p.endswith('.json')]
    rows=[json.JSONDecoder().raw_decode(files[p].lstrip())[0] for p in record_paths]
    rows=[r for r in rows if 'session_id' in r]
    if len(rows)!=3 or {r['nonce'] for r in rows}!={'counter0','counter1','counter2'}: errors.append('capture_set')
    for label in ORDER:
        ev=value(label+'-evidence.json'); logs=[files[prefix+label+'-%d.log'%i] for i in range(2)]
        actors=[operations(log,ev['window']) for log in logs]
        if ev['exit_codes']!=[0,0]: errors.append('workload_exit_'+label)
        for i,actor in enumerate(actors):
            before,after=[ev[edge]['roots'][i] for edge in ('before','after')]
            cb,ca=counts(before['cpu.stat']),counts(after['cpu.stat'])
            actor['cgroup_cpu_delta_usec']={key:ca[key]-cb[key] for key in cb}
            actor['cgroup_cpu_scope']='includes launch and teardown between snapshots, not solely operations or observer'
            actor['memory_before_bytes']=int(before['memory.current'])
            actor['memory_after_bytes']=int(after['memory.current'])
            actor['memory_peak_bytes']=int(after['memory.peak'])
            actor['memory_peak_scope']='cumulative since root creation, not reset between modes'
            eb,ea=counts(before['memory.events']),counts(after['memory.events'])
            actor['memory_events_delta']={key:ea[key]-eb[key] for key in eb}
            if any(actor['memory_events_delta'].get(k,0)!=0 for k in ('oom','oom_kill','oom_group_kill','max')):
                errors.append('memory_failure_'+label)
        entry=dict(label=label,actors=actors,complete_observer_cost='UNKNOWN')
        if label.startswith('counter'):
            matching=[r for r in rows if r['nonce']==label]
            if len(matching)!=1: raise ValueError('missing unique capture')
            record=matching[0]; sid=str(record['session_id'])
            if record['window']!=ev['window'] or sid!=str(ev['session_id']): errors.append('window_binding_'+label)
            if any(record.get(k)!=permit['source'].get(k) for k in SOURCE_KEYS): errors.append('session_source_'+label)
            validate_inventory('counter',record['inventory'])
            raw=(files[prefix+'records/'+sid+'.jsonl'].rstrip()+'\n').encode()
            report=analyze(record,raw); scope=audit(record,raw)
            bridge=check(record,report,logs,[record['root_identities'][k] for k in ev['targets']])
            if bridge['status']!='PASS' or scope['status']!='PASS': errors.append('bridge_'+label)
            validate(ev['active_sources'],'counter',record['requested_ns'],record['window']['end_ns'])
            entry.update(bridge=bridge,scope_audit=scope['status'],
                         process_capturing_cpu_ns=record['process_cpu_budget']['phase_peak_cpu_ns']['CAPTURING'],
                         combined_process_rss_peak_bytes=record['combined_rss_peak_bytes'],
                         excluded=report['excluded'])
            for suffix,obj in (('record',record),('report',report),('bridge',bridge),('scope',scope)):
                (output/(label+'.'+suffix+'.json')).write_text(json.dumps(obj,indent=2))
            (output/(label+'.jsonl')).write_bytes(raw)
        else:
            if ev['session_id'] is not None: errors.append('off_has_session')
            validate(ev['active_sources'],None,ev['window']['start_ns'],ev['window']['end_ns'])
        validate(ev['idle_sources'],None,ev['window']['start_ns'],2**64-1)
        states.append(entry)
    pairs=[]
    for repeat in range(3):
        off=next(s for s in states if s['label']=='off'+str(repeat))
        on=next(s for s in states if s['label']=='counter'+str(repeat))
        for i in range(2):
            a,b=off['actors'][i],on['actors'][i]
            pairs.append(dict(round=repeat,actor_index=i,
                              operations_per_second_change_pct=(b['operations_per_second']/a['operations_per_second']-1)*100,
                              operation_median_wall_change_pct=(statistics.median(b['operation_wall_ns'])/statistics.median(a['operation_wall_ns'])-1)*100,
                              cgroup_cpu_delta_usec=b['cgroup_cpu_delta_usec']['usage_usec']-a['cgroup_cpu_delta_usec']['usage_usec']))
    report=dict(status='FAIL' if errors else 'PASS',errors=sorted(set(errors)),states=states,paired_descriptive_changes=pairs,
                source=result['source'],serial_sha256=hashlib.sha256(data).hexdigest(),
                scope='ordinary native memcg path bridge with default sampling, not full X2 or X7 acceptance',
                performance_certification='NOT_ACCEPTED',causal_claim='NONE',
                pending=['source-entry and async CPU','complete observer memory','native object lifetime','hardware contention proof'])
    (output/'verification.json').write_text(json.dumps(report,indent=2))
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('serial',type=Path); p.add_argument('output',type=Path)
    args=p.parse_args(); result=verify(args.serial,args.output)
    print(json.dumps(dict(status=result['status'],errors=result['errors'],states=len(result['states']))))
    raise SystemExit(result['status']!='PASS')
