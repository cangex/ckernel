# SPDX-License-Identifier: GPL-2.0
"""Over-budget queue capture rejection and source-off while traffic continues."""
import argparse
import json
from pathlib import Path
from owner_report import fields
from queue_report import analyze
from y5_queue_check import source_delta
from source_switches import validate
from session_check import extract


def order():
    return [dict(label='stormR%d%s'%(r,'On' if on else 'Off'),case='storm',round=r,enabled=on)
            for r in range(1,4) for on in ((False,True) if r%2 else (True,False))]


def check(record,raw,logs,evidence):
    errors=[]; progress=[]; reason='OFF'
    native=source_delta(evidence['before']['native'],evidence['after']['native'])
    quiet=source_delta(evidence['detached']['native'],evidence['after']['native'])
    validate(evidence['idle_sources'],None,0,2**64-1)
    if any(quiet.values()): errors.append('source_still_active_after_detach')
    for i,text in enumerate(logs):
        rows=[fields(l) for l in text.splitlines() if l.startswith('CIS_QUEUE_BUCKET ')]
        if (len(rows)!=8 or [r.get('bucket') for r in rows]!=list(range(8)) or
                any(r.get('actor')!=i or r.get('operations',0)<=0 or r.get('errors')!=0 or
                    not 0<r.get('begin_ns',0)<r.get('end_ns',0) for r in rows)):
            errors.append('business_progress'); continue
        after=[r for r in rows if r['begin_ns']>evidence['detached']['after_ns']]
        if not after: errors.append('no_post_detach_business')
        progress.append(sum(r['operations'] for r in after))
    if record is None:
        validate(evidence['active_sources'],None,0,2**64-1)
        if any(native.values()): errors.append('off_not_quiet')
    else:
        validate(evidence['active_sources'],'qdisc',record['requested_ns'],record['window']['end_ns'])
        receipt=record.get('receipt',{}); reason=receipt.get('reason')
        budget=record.get('process_cpu_budget',{}); controller=reason=='CANCELLED' and record.get('budget_reason')=='COMBINED_PROCESS_CPU_CAPTURING'
        if controller: reason=record['budget_reason']
        if (record.get('result')!='PARTIAL' or record.get('objects_absent') is not True or
                record.get('finalized') is not True or record.get('state')!='IDLE' or receipt.get('stop_error')):
            errors.append('partial_or_cleanup')
        rows=[json.loads(l) for l in raw.splitlines()]; rates=[fields(r['detail']) for r in rows if r.get('kind')=='entry_budget_disable']
        if reason=='ENTRY_RATE_LIMIT':
            if len(rates)!=1 or rates[0].get('configured_limit')!=200000 or not (
                    rates[0].get('delta_entries',0)*10**9>200000*rates[0].get('interval_ns',10**30)):
                errors.append('entry_guard_proof')
        elif reason=='WORKER_CPU_LIMIT':
            if receipt.get('armed_capture_cpu_ns',0)<=20000000: errors.append('worker_guard_proof')
        elif reason=='COMBINED_PROCESS_CPU_CAPTURING':
            first=budget.get('first_violation',{})
            if first.get('reason')!=reason or first.get('phase_limit_ns')!=40000000 or first.get('phase_cpu_ns',0)<=40000000:
                errors.append('controller_guard_proof')
        elif reason=='QUALITY':
            if receipt.get('terminal',{}).get('lost',0)<=0: errors.append('quality_without_loss')
        else: errors.append('unexpected_guard_reason')
        report=analyze(record,raw)
        if report['quality']['status']=='PASS' or report['shared_resources'] or any(r['evidence']!='UNACCEPTED' for r in report['samples']):
            errors.append('rejected_capture_promoted')
        if native['entries']<1000: errors.append('no_source_pressure')
    return dict(status='FAIL' if errors else 'PASS_PROTECTION_ONLY',errors=errors,reason=reason,
        native=native,quiet=quiet,post_detach_operations=progress,
        scope='protection and continued business, not attribution or performance acceptance')


def replay(serial,output):
    if serial.stat().st_size>128<<20: raise ValueError('serial capacity')
    text=serial.read_text(); files=extract(text); prefix='/tmp/y5-queue-guard/'
    def value(path): return json.JSONDecoder().raw_decode(files[prefix+path].lstrip())[0]
    declared=value('result.json'); states=declared['states']; errors=[]; checked=[]
    if [{k:s[k] for k in ('label','case','round','enabled')} for s in states]!=order(): errors.append('order')
    if 'CIS_PROFILE_VM_EXIT=0' not in text.splitlines() or 'CIS_QUEUE_DEVICE_UNLOAD=0' not in text.splitlines(): errors.append('exit_or_unload')
    if any(s in text for s in ('BUG: KASAN:','Oops:','Kernel panic','WARNING: CPU:')): errors.append('kernel_warning')
    for e in states:
        record=None; raw=None; label=e['label']
        if e['session_id']:
            sid=e['session_id']; record=value('records/'+sid+'.json')
            raw=(files[prefix+'records/'+sid+'.jsonl'].rstrip()+'\n').encode()
        r=check(record,raw,[files[prefix+label+'-%d.log'%i] for i in range(2)],e)
        if r['status']!='PASS_PROTECTION_ONLY' or e['exit_codes']!=[0,0]: errors.append(label+':'+str(r['errors']))
        checked.append(dict(label=label,result=r))
    output.mkdir(mode=0o700); result=dict(status='FAIL' if errors else 'PASS_PROTECTION_ONLY',errors=errors,states=checked)
    (output/'replay.json').write_text(json.dumps(result,indent=2)); print(json.dumps(dict(status=result['status'],errors=errors)))
    return bool(errors)


if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('serial',type=Path); p.add_argument('output',type=Path)
    a=p.parse_args(); raise SystemExit(replay(a.serial,a.output))
