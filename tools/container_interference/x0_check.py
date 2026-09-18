#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Check X0 raw VM artifacts; a result string alone cannot grant completion."""
import argparse
import hashlib
import json
from pathlib import Path

from collector_audit import audit as scope_audit
from collector_manifest import validate_inventory
from session_check import extract
from prototype_admission import SOURCE_KEYS

CONTROL = {'selective_load_ip', 'selective_load_owner', 'selective_load_sched', 'selective_load_reclaim',
           'pause_drain_and_shared_manual_budget', 'restart_paused_nonce_and_budget_preserved',
           'unregister_removes_future_target', 'real_missed_slots_not_replayed'}


def check(text):
    if len(text.encode()) > 128 << 20: raise ValueError('serial input limit')
    files = extract(text); prefix = '/tmp/prototype-evidence/'
    def value(name): return json.JSONDecoder().raw_decode(files[prefix+name].lstrip())[0]
    plan, result, permit = [value(name+'.json') for name in ('plan', 'result', 'permit')]
    if plan.get('schema') != 'cis-x0-plan-v1' or result.get('schema') != 'cis-x0-result-v1':
        raise ValueError('unsupported X0 result protocol')
    checks = result['checks']
    expected = ({'real_permit_expiry'} if plan['expiry'] else
                {'failed_verification_blocks_admission'} if plan['fault'] else CONTROL)
    defects = []
    if set(row['name'] for row in checks) != expected or len(checks) != len(expected): defects.append('incomplete_check_set')
    if any(row.get('status') != 'PASS' for row in checks): defects.append('case_failed')
    if 'CIS_PROFILE_VM_EXIT=0' not in text.splitlines(): defects.append('guest_exit')
    requests = [json.loads(line) for line in files[prefix+'requests.jsonl'].splitlines() if line.startswith('{')]
    if not requests or len(requests)>5000: raise ValueError('request audit capacity')
    for i, row in enumerate(requests):
        if (row['sequence'] != i+1 or row['before_ns'] > row['after_ns'] or
                (i and row['before_ns'] < requests[i-1]['after_ns'])): defects.append('request_timeline')
    def ops(name, ok=True):
        return [row for row in requests if row['request']['op'] == name and row['response']['ok'] is ok]
    source = result['source']
    if not isinstance(source, dict) or not all(key in source for key in SOURCE_KEYS):
        raise ValueError('incomplete source identity')
    if source != plan['source'] or any(permit['source'].get(key) != source.get(key) for key in permit['source']):
        defects.append('source_binding')
    records = []
    for path, body in files.items():
        if path.startswith(prefix+'records/') and path.endswith('.json'):
            row = json.JSONDecoder().raw_decode(body.lstrip())[0]
            if 'session_id' in row: records.append(row)
    scope = []
    for row in records:
        if any(row.get(key) != source.get(key) for key in permit['source']): defects.append('session_source')
        raw = files.get(prefix+'records/'+str(row['session_id'])+'.jsonl', '').encode()
        # Absence of new scope counters in older cohorts stays BLOCKED.
        scope.append(dict(session=row['session_id'], **scope_audit(row, raw)))
    if plan['expiry']:
        if records or permit['expires_ns']-permit['created_ns'] != 1200*10**9:
            defects.append('expiry_contract')
        for operation in ('start', 'schedule_enable'):
            if not any(row['before_ns'] >= permit['expires_ns'] for row in ops(operation, False)):
                defects.append('expiry_'+operation)
    elif plan['fault']:
        if len(records) != 1 or records[0].get('state') != 'FAULTED' or records[0].get('objects_absent') is not False:
            defects.append('fault_not_retained')
        if not ops('start', False): defects.append('fault_admission_not_rejected')
    else:
        for collector in ('ip', 'owner', 'sched', 'reclaim'):
            rows = [r for r in records if r['nonce'] == 'load'+collector]
            if len(rows) != 1 or rows[0].get('result') != 'COMPLETE' or rows[0].get('objects_absent') is not True:
                defects.append('load_'+collector)
            else: validate_inventory(collector, rows[0]['inventory'])
        if not ops('schedule_pause') or not ops('unregister') or not ops('unregister', False):
            defects.append('pause_unregister_audit')
        rejected = {row['request'].get('nonce') for row in ops('start', False)}
        if not {'tooearly', 'oldnonce', 'restartbudget'} <= rejected: defects.append('budget_or_nonce_audit')
        status = [row['response']['data'] for row in ops('schedule_status')]
        if not any(x.get('skipped', {}).get('missed_slots', 0) >= 1 for x in status): defects.append('missed_slot_audit')
        if not any(x.get('enabled') is False and x.get('roots') == {} for x in status): defects.append('restart_paused_audit')
    return dict(schema='cis-x0-check-v1', status='FAIL' if defects else 'PASS', defects=sorted(set(defects)),
                source=source, expected_cases=len(expected), sessions=len(records), scope_audit=scope,
                scope_audit_complete=all(row['status']=='PASS' for row in scope),
                serial_sha256=hashlib.sha256(text.encode()).hexdigest(),
                performance_certification='NOT_ACCEPTED', checks=checks)


if __name__ == '__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('serial'); parser.add_argument('output')
    args=parser.parse_args()
    if Path(args.serial).stat().st_size > 128 << 20: raise ValueError('serial input limit')
    result=check(Path(args.serial).read_text())
    with Path(args.output).open('x') as stream: json.dump(result, stream, indent=2)
    print(json.dumps({key:result[key] for key in ('status','defects','expected_cases','sessions','scope_audit_complete')}))
    raise SystemExit(0 if result['status']=='PASS' else 1)
