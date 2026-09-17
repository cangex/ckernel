# SPDX-License-Identifier: GPL-2.0
"""Read bounded runtime subclaims without promoting them to full acceptance."""
import json
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
    check('real_fd_exhaustion', ['fdLimit%d'%i for i in range(4,25)],
          lambda r: r.get('result') in ('PARTIAL','COMPLETE') and r.get('objects_absent') is True and bool(r.get('receipt')),
          'predeclared RLIMIT_NOFILE 4..24 sweep; not all resource failures')
    return dict(schema='cis-runtime-subclaims-v1', subchecks=checks,
                raw_clean_exit=clean_exit, full_lifecycle_complete=False,
                full_resource_failures_complete=False,
                remaining=['crash/restart and control backpressure cross-checks',
                           'ARM/DRAIN/publish storage failures and bounded recovery',
                           'allocator-internal coverage and combined CPU enforcement evidence'])
