# SPDX-License-Identifier: GPL-2.0
"""A rejected dense capture may pass protection, never attribution coverage."""
import argparse
import errno
import hashlib
import json
from pathlib import Path
from net_report import analyze
from net_source_audit import delta
from net_fixture_check import case_order
from owner_report import fields
from session_check import extract
from source_switches import validate
from prototype_admission import SOURCE_KEYS


def check(record,raw,logs,evidence):
    errors=[]; progress=[]; cookies=[]; rate=[]; counters={}
    active=evidence['active_sources']; idle=evidence['idle_sources']
    source=delta(evidence['source_before'],evidence['source_after'])
    quiet=delta(evidence['source_detached'],evidence['source_after'])
    validate(idle,None,0,2**64-1)
    if any(quiet['totals'].values()): errors.append('callbacks_after_detach')
    if len(logs)!=2: errors.append('actor_count')
    for actor,text in enumerate(logs):
        buckets=[json.loads(line.split(' ',1)[1]) for line in text.splitlines() if line.startswith('CIS_NET_STORM ')]
        if (len(buckets)!=8 or [b.get('bucket') for b in buckets]!=list(range(8)) or
                any(b.get('actor')!=actor or b.get('errors')!=0 or b.get('operations',0)<=0 or
                    b.get('end_ns',0)<=b.get('begin_ns',0) or not b.get('cookie') for b in buckets)):
            errors.append('business_progress'); continue
        unique={b['cookie'] for b in buckets}
        if len(unique)!=1: errors.append('private_socket_changed')
        cookies.extend(unique)
        after=[b for b in buckets if b['begin_ns']>idle['after_ns']]
        if not after: errors.append('no_business_after_detach')
        progress.append(sum(b['operations'] for b in after))
    if len(set(cookies))!=2: errors.append('private_socket_identity')
    if record is None:
        validate(active,None,0,2**64-1)
        if any(source['totals'].values()): errors.append('off_not_quiet')
        reason='OFF'
    else:
        report=analyze(record,raw); receipt=record.get('receipt',{}); reason=receipt.get('reason')
        controller_stop=reason=='CANCELLED' and record.get('budget_reason')=='COMBINED_PROCESS_CPU_CAPTURING'
        if controller_stop: reason=record['budget_reason']
        validate(active,'net',record['requested_ns'],record['window']['end_ns'])
        if (record.get('collector')!='net' or record.get('result')!='PARTIAL' or
                receipt.get('result')!=('CANCELLED' if controller_stop else 'PARTIAL') or
                not record.get('finalized') or record.get('state')!='IDLE' or record.get('objects_absent') is not True):
            errors.append('capture_or_cleanup')
        events=[json.loads(line) for line in raw.splitlines()]
        for e in events:
            if e.get('kind')=='entry_budget_disable': rate.append(fields(e['detail']))
            if e.get('kind') in ('terminal_counters','terminal_coverage'): counters.update(fields(e['detail']))
        if reason=='ENTRY_RATE_LIMIT':
            if len(rate)!=1 or rate[0].get('configured_limit')!=200000 or not (
                    rate[0].get('interval_ns',0)>0 and rate[0].get('delta_entries',0)*10**9>200000*rate[0]['interval_ns']):
                errors.append('entry_stop_without_rate_proof')
        elif reason=='WORKER_CPU_LIMIT':
            if receipt.get('armed_capture_cpu_ns',0)<=20000000: errors.append('cpu_stop_without_cost')
        elif reason=='COMBINED_PROCESS_CPU_CAPTURING':
            budget=record.get('process_cpu_budget',{}); first=budget.get('first_violation',{})
            if (budget.get('violation')!=reason or first.get('reason')!=reason or first.get('phase')!='CAPTURING' or
                    budget.get('phase_limits_ns',{}).get('CAPTURING')!=40000000 or
                    first.get('phase_limit_ns')!=40000000 or first.get('phase_cpu_ns',0)<=40000000 or
                    budget.get('phase_peak_cpu_ns',{}).get('CAPTURING',0)<first.get('phase_cpu_ns',0)):
                errors.append('combined_cpu_stop_without_fixed_limit_proof')
        elif reason=='QUALITY':
            if counters.get('lost',0)<=0: errors.append('quality_stop_without_ring_loss')
        elif reason=='DATA_LIMIT':
            if not ((16<<20)-2048<=len(raw)<=16<<20 and receipt.get('output_error')==errno.EFBIG and
                    receipt.get('bytes')==len(raw)): errors.append('data_stop_without_output')
        else: errors.append('unexpected_stop_reason')
        if (report['quality']['status']!='FAIL' or report['sockets'] or report['tx']['episodes']):
            errors.append('incomplete_capture_admitted_relations')
        if source['totals']['selected']<1000: errors.append('no_native_event_pressure')
    return dict(status='FAIL' if errors else 'PASS',errors=errors,reason=reason,rates=rate,
        counters=counters,post_detach_operations=progress,source_audit=source,
                scope='dense private Socket protection and business continuation, not attribution or performance acceptance')


def verify(serial,output):
    if serial.stat().st_size>128<<20: raise ValueError('serial capacity')
    raw=serial.read_bytes(); text=raw.decode(); files=extract(text); prefix='/tmp/net-evidence/'
    def value(name): return json.JSONDecoder().raw_decode(files[prefix+name].lstrip())[0]
    plan,declared,permit=[value(k+'.json') for k in ('plan','result','permit')]
    expected=dict(schema='cis-net-guard-v1',order=case_order(('storm',)),rounds=3,seconds=4,
        buckets=8,bucket_ns=500000000,window_ms=2000,entry_rate_limit=200000,roots=2,
        cpu=[0,1],management_cpu=7,net_shift=0,sockets_per_actor=1,hold_ms=0)
    output.mkdir(mode=0o700); errors=[]; states=[]
    if plan!=expected: errors.append('frozen_plan')
    if any(declared['source'].get(k)!=permit['source'].get(k) for k in SOURCE_KEYS): errors.append('source_binding')
    if 'CIS_PROFILE_VM_EXIT=0' not in text.splitlines() or 'CIS_NET_FIXTURE_UNLOAD=0' not in text.splitlines():
        errors.append('guest_exit_or_unload')
    if any(s in text for s in ('BUG: KASAN:','Oops:','Kernel panic','WARNING: CPU:')): errors.append('kernel_warning')
    for label in expected['order']:
        ev=value(label+'-evidence.json'); record=None; capture=None
        if '-net' in label:
            sid=str(ev['session_id'])
            if not sid.isascii() or not sid.isdigit(): raise ValueError('session identity')
            record=value('records/'+sid+'.json'); capture=(files[prefix+'records/'+sid+'.jsonl'].rstrip()+'\n').encode()
            if record['nonce']!=label.replace('-','') or any(record.get(k)!=permit['source'].get(k) for k in SOURCE_KEYS):
                errors.append('record_identity_'+label)
        result=check(record,capture,[files[prefix+label+'-%d.log'%i] for i in range(2)],ev)
        if result['status']!='PASS' or ev['exit_codes']!=[0,0]: errors.append(label)
        states.append(dict(label=label,result=result))
    result=dict(status='FAIL' if errors else 'PASS',errors=errors,states=states,source=declared['source'],
                serial_sha256=hashlib.sha256(raw).hexdigest(),attribution_certification='NOT_ACCEPTED')
    (output/'verification.json').write_text(json.dumps(result,indent=2)); return result


if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('serial',type=Path); p.add_argument('output',type=Path); a=p.parse_args()
    r=verify(a.serial,a.output); print(json.dumps(dict(status=r['status'],errors=r['errors'],states=len(r['states']))))
    raise SystemExit(r['status']!='PASS')
