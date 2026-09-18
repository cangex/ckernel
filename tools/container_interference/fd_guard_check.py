# SPDX-License-Identifier: GPL-2.0
"""Protection PASS requires a rejected, PARTIAL profiling window."""
import json
import argparse
import hashlib
from pathlib import Path

from collector_manifest import validate_inventory
from explain import explain
from owner_report import fields
from source_switches import validate as validate_sources
from session_check import extract
from prototype_admission import SOURCE_KEYS


def check(record,raw,logs,sources):
    validate_inventory('fd',record['inventory'])
    if record.get('collector')!='fd': raise ValueError('FD guard collector')
    errors=[]
    report=explain(record,raw)
    receipt=record.get('receipt') or {}
    if (record.get('result')!='PARTIAL' or receipt.get('result')!='PARTIAL' or not record.get('finalized') or
            record.get('state')!='IDLE' or record.get('objects_absent') is not True):
        errors.append('capture_or_cleanup_state')
    if receipt.get('reason')!='ENTRY_RATE_LIMIT': errors.append('wrong_stop_reason')
    events=[json.loads(line) for line in raw.splitlines()]
    rates=[fields(event['detail']) for event in events if event.get('kind')=='entry_budget_disable']
    if len(rates)!=1 or rates[0].get('configured_limit')!=200000 or not (
            rates[0].get('interval_ns',0)>0 and
            rates[0].get('delta_entries',0)*10**9>200000*rates[0]['interval_ns']):
        errors.append('missing_fixed_rate_proof')
    if report['quality']['status']!='FAIL' or report['finding_count']:
        errors.append('incomplete_capture_admitted_findings')
    validate_sources(sources['active'],'fd',record['requested_ns'],record['window']['end_ns'])
    validate_sources(sources['idle'],None,record['requested_ns'],2**64-1)
    progress=[]
    if len(logs)!=2: errors.append('business_count')
    for text in logs:
        buckets=[json.loads(line.split(' ',1)[1]) for line in text.splitlines() if line.startswith('CIS_FD_STORM ')]
        if (len(buckets)!=8 or [row['bucket'] for row in buckets]!=list(range(8)) or
                any(row['errors'] or row['operations']<=0 or row['end_ns']<=row['begin_ns'] for row in buckets)):
            errors.append('business_progress_protocol')
        after=[row for row in buckets if row['begin_ns']>sources['idle']['after_ns']]
        if not after: errors.append('no_business_progress_after_source_detach')
        progress.append(sum(row['operations'] for row in after))
    return dict(status='FAIL' if errors else 'PASS',errors=errors,rates=rates,
                post_detach_operations=progress,capture_status=record.get('result'),
                scope='entry guard and business continuation, not successful dense profiling',
                performance_certification='NOT_ACCEPTED')


def verify(serial,output):
    if serial.stat().st_size>128<<20: raise ValueError('serial capacity')
    raw=serial.read_bytes();text=raw.decode();files=extract(text);prefix='/tmp/fd-guard-evidence/'
    def value(name): return json.JSONDecoder().raw_decode(files[prefix+name].lstrip())[0]
    declared,plan,permit=[value(name+'.json') for name in ('result','plan','permit')]
    output.mkdir(mode=0o700);errors=[];cases=[]
    if 'CIS_PROFILE_VM_EXIT=0' not in text.splitlines(): errors.append('guest_exit')
    expected={key:value for key,value in dict(schema='cis-fd-guard-v1',repetitions=3,off_rounds=1,
        seconds=4,window_ms=2000,collector='fd',entry_rate_limit=200000).items()}
    if any(plan.get(key)!=item for key,item in expected.items()): errors.append('frozen_plan')
    if any(permit['source'].get(k)!=declared['source'].get(k) or
           plan['source'].get(k)!=declared['source'].get(k) for k in SOURCE_KEYS): errors.append('source_binding')
    rows=[]
    for path,body in files.items():
        if path.startswith(prefix+'records/') and path.endswith('.json'):
            row=json.JSONDecoder().raw_decode(body.lstrip())[0]
            if 'session_id' in row: rows.append(row)
    if len(rows)!=3 or {row['nonce'] for row in rows}!={'storm0','storm1','storm2'}: errors.append('fixed_sessions')
    if len(declared['cases'])!=3: errors.append('declared_cases')
    for row in rows:
        sid=str(row['session_id']);label=row['nonce']
        if not sid.isascii() or not sid.isdigit(): raise ValueError('session id')
        if any(row.get(k)!=permit['source'].get(k) for k in SOURCE_KEYS): errors.append('session_source')
        markers=[item for item in declared['cases'] if item['label']==label and str(item['session_id'])==sid]
        if len(markers)!=1: raise ValueError('case identity')
        capture=(files[prefix+'records/'+sid+'.jsonl'].rstrip()+'\n').encode()
        result=check(row,capture,[files[prefix+label+'-%d.log'%i] for i in range(2)],markers[0]['sources'])
        if result['status']!='PASS': errors.append('guard_'+label)
        cases.append(dict(label=label,**result))
        (output/(sid+'.record.json')).write_text(json.dumps(row,indent=2))
        (output/(sid+'.jsonl')).write_bytes(capture)
    off=value('off-sources.json')
    for side in ('before','after'): validate_sources(off[side],None,0,2**64-1)
    for index in range(2):
        buckets=[json.loads(line.split(' ',1)[1]) for line in files[prefix+'off-%d.log'%index].splitlines()
                 if line.startswith('CIS_FD_STORM ')]
        if len(buckets)!=8 or any(not off['before']['after_ns']<=item['begin_ns']<item['end_ns']<=off['after']['before_ns'] or
                                 item['errors'] or item['operations']<=0 for item in buckets): errors.append('off_smoke')
    result=dict(schema='cis-fd-guard-check-v1',status='FAIL' if errors else 'PASS',errors=sorted(set(errors)),cases=cases,
                source=declared['source'],serial_sha256=hashlib.sha256(raw).hexdigest(),
                analyzer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                dense_fd_collection='NOT_ACCEPTED',performance_certification='NOT_ACCEPTED')
    (output/'verification.json').write_text(json.dumps(result,indent=2));return result


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('serial',type=Path);parser.add_argument('output',type=Path)
    args=parser.parse_args();result=verify(args.serial,args.output)
    print(json.dumps({key:result[key] for key in ('status','errors','cases')}))
    raise SystemExit(result['status']!='PASS')
