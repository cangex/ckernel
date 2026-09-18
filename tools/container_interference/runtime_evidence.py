# SPDX-License-Identifier: GPL-2.0
"""Read bounded runtime subclaims without promoting them to full acceptance."""
import json
import re
from pathlib import PurePosixPath

from session_check import extract
from session_quality import assess

STAGES = ('object_load', 'cpu_stats', 'output_perf_buffer', 'ip_perf_fd',
          'ip_perf_mmap', 'ip_perf_attach', 'owner_attach', 'window_map')


def analyze(text, source):
    files = extract(text)
    records = {}
    for name, body in files.items():
        if '/records/' not in name or not name.endswith('.json'):
            continue
        record, _ = json.JSONDecoder().raw_decode(body.lstrip())
        identity = record.get('source_identity') or record
        if {k: identity.get(k) for k in source} != source:
            raise ValueError('runtime source mismatch')
        sid = str(record['session_id'])
        if PurePosixPath(name).stem != sid or sid in records:
            raise ValueError('runtime record identity/path mismatch')
        records[sid] = record
    nonces = {}
    for sid, record in records.items():
        nonce = record.get('nonce')
        if nonce in nonces:
            raise ValueError('duplicate runtime nonce')
        nonces[nonce] = sid
    exits = [x for x in text.splitlines() if x.startswith('CIS_PROFILE_VM_EXIT=')]
    clean_exit = exits == ['CIS_PROFILE_VM_EXIT=0']
    checks = {}

    def check(name, required, predicate, scope):
        missing = [nonce for nonce in required if nonce not in nonces]
        defects = [nonce for nonce in required if nonce in nonces and not predicate(records[nonces[nonce]])]
        status = 'FAIL' if defects or (required and not clean_exit) else 'BLOCKED' if missing else 'PASS'
        checks[name] = dict(status=status, missing=missing, defects=defects,
                            session_ids=[nonces[n] for n in required if n in nonces], scope=scope)

    check('sampled_functional', ['functionalip','functionalowner'],
          lambda r: assess(r)['status']=='PASS', 'two bounded sampled sessions; not cost acceptance')
    check('cancellation', ['cancelSlowAdmission','cancelPrepare','cancelActive'],
          lambda r: r.get('result')=='CANCELLED' and r.get('objects_absent') is True and r.get('finalized') is True,
          'durable cancellation at three stages; does not cover process crashes')

    def injected(record):
        if record.get('result')!='PARTIAL' or record.get('objects_absent') is not True:
            return False
        sid = str(record['session_id'])
        streams = [body for path, body in files.items() if path.endswith('/records/'+sid+'.jsonl')]
        if len(streams)!=1:
            return False
        events = [json.loads(line) for line in streams[0].splitlines() if line.startswith('{')]
        if any(str(event.get('session_id'))!=sid for event in events):
            return False
        faults = [event for event in events if event.get('kind')=='fault_injection']
        expected = [stage for stage in STAGES if 'stage'+stage.replace('_','') == record.get('nonce')]
        return len(expected)==1 and len(faults)==1 and ('stage='+expected[0]+' ') in faults[0].get('detail','')

    check('boundary_failures', ['stage'+stage.replace('_','') for stage in STAGES], injected,
          'eight injected boundaries, not allocator-internal exhaustive faults')
    def fd_exhaustion(record):
        if record.get('result') not in ('PARTIAL','COMPLETE') or record.get('objects_absent') is not True or not record.get('receipt'):
            return False
        streams=[body for path,body in files.items() if path.endswith('/records/'+str(record['session_id'])+'.jsonl')]
        if len(streams)!=1:return False
        events=[json.loads(line) for line in streams[0].splitlines() if line.startswith('{')]
        if any(str(e.get('session_id'))!=str(record['session_id']) for e in events):return False
        limits=[dict(re.findall(r'(\w+)=([^ ;]+)',e.get('detail',''))) for e in events if e.get('kind')=='fault_injection' and 'stage=fd_limit ' in e.get('detail','')]
        value=record['nonce'][len('fdLimit'):]
        return len(limits)==1 and all(limits[0].get(k)==value for k in ('requested','soft','hard'))

    check('real_fd_exhaustion', ['fdLimit%d'%i for i in range(4,25)], fd_exhaustion,
          'predeclared RLIMIT_NOFILE 4..24 sweep; not all resource failures')
    if checks['real_fd_exhaustion']['status']=='PASS' and not any(records[nonces['fdLimit%d'%i]]['result']=='PARTIAL' for i in range(4,25)):
        checks['real_fd_exhaustion'].update(status='FAIL', defects=['no limit-induced partial case observed'])
    inventories=[body for path,body in files.items() if path.endswith('/resource-inventories.json')]
    restored=dict(status='BLOCKED',reason='raw before/after inventory absent')
    if len(inventories)>1:raise ValueError('duplicate resource inventory audit')
    if inventories:
        audit,_=json.JSONDecoder().raw_decode(inventories[0].lstrip())
        baseline=audit['before'];seen=set();wrong=[];previous=-1
        def valid_snapshot(value):
            return isinstance(value,dict) and set(value)=={'maps','programs'} and all(
                isinstance(v,list) and len(v)<=4096 and all(type(x) is int and x>0 for x in v) and v==sorted(set(v))
                for v in value.values())
        if not valid_snapshot(baseline):raise ValueError('invalid baseline BPF inventory')
        for row in audit['checks']:
            nonce=row['nonce']
            if nonce in seen or row['time_ns']<previous:raise ValueError('duplicate/unordered inventory audit')
            seen.add(nonce);previous=row['time_ns']
            if not valid_snapshot(row['after']):raise ValueError('invalid final BPF inventory')
            if nonce not in nonces or str(row['session_id'])!=nonces[nonce] or row['after']!=baseline:
                wrong.append(nonce)
        required={'fdLimit%d'%i for i in range(4,25)}|{'stage'+s.replace('_','') for s in STAGES}
        restored=dict(status='FAIL' if wrong else 'PASS' if seen==required else 'BLOCKED',
                      missing=sorted(required-seen),defects=wrong,
                      scope='enumerable BPF inventory restored, not deferred memory/CPU reclamation')
    checks['inventory_restoration']=restored
    from lifecycle_evidence import analyze as lifecycle_analyze
    checks['crash_recovery']=lifecycle_analyze(files,records,clean_exit)
    return dict(schema='cis-runtime-subclaims-v1', subchecks=checks,
                raw_clean_exit=clean_exit, full_lifecycle_complete=False,
                full_resource_failures_complete=False,
                remaining=['crash/restart and control backpressure cross-checks',
                           'ARM/DRAIN/publish storage failures and bounded recovery',
                           'allocator-internal coverage and combined CPU enforcement evidence'])
