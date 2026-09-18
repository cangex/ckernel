# SPDX-License-Identifier: GPL-2.0
"""Fixed VM truth checker. Truth never upgrades production E1 candidates."""
from owner_report import fields


def check(report, logs, shared=True, failure=False):
    defects, truth = [], []
    for log in logs:
        pids=[fields(line).get('host_pid') for line in log.splitlines() if line.startswith('CIS_SESSION_CONTAINER ')]
        if len(pids)!=1 or not pids[0]: defects.append('missing_container_pid'); continue
        truth.extend(dict(fields(line), host_pid=pids[0]) for line in log.splitlines() if line.startswith('CIS_COUNTER_TRUTH '))
    if report['quality']['status'] != 'PASS': defects.append('capture_quality')
    if not truth: defects.append('missing_truth')
    eligible, matched = 0, 0
    fixture_leaves = {r['leaf'] for r in truth}
    fixture_calls = [c for c in report['calls'] if c['leaf_address'] in fixture_leaves]
    for t in truth:
        if bool(t['failed']) != failure or bool(t['success']) == failure:
            defects.append('unexpected_native_result')
        if t['final_leaf'] < 0 or t['final_parent'] < 0: defects.append('counter_underflow')
        expected = ['try_charge'] if failure else ['charge' if t['operation']==0 else 'try_charge', 'uncharge']
        for op in expected:
            eligible += 1
            found = [c for c in fixture_calls if c['leaf_address']==t['leaf'] and c['operation']==op and
                     t['begin_ns'] <= c['interval_ns'][0] <= c['interval_ns'][1] <= t['end_ns']]
            if len(found) != 1:
                defects.append('missing_or_duplicate_call'); continue
            c=found[0]
            if c['actor'][2] & 0xffffffff != t['host_pid']: defects.append('wrong_task_identity')
            observed={s['address'] for s in c['steps'] if s['stage'] in ('usage_add','usage_sub')}
            if observed != {t['leaf'], t['parent']}: defects.append('wrong_actual_hierarchy')
            if failure and c['failure_address'] != t['failed']: defects.append('wrong_failure_ancestor')
            matched += 1
    extra=[c for c in fixture_calls if not any(t['leaf']==c['leaf_address'] and
            t['begin_ns']<=c['interval_ns'][0]<=c['interval_ns'][1]<=t['end_ns'] for t in truth)]
    if extra: defects.append('outside_truth_call')
    fixture_addresses=fixture_leaves | {r['parent'] for r in truth}
    candidates=[c for c in report['address_candidates'] if c['address'] in fixture_addresses and c['field']=='usage']
    if bool(candidates) != shared: defects.append('shared_private_candidate_mismatch')
    return dict(status='FAIL' if defects else 'PASS', defects=sorted(set(defects)), truth_operations=len(truth),
                eligible_calls=eligible, matched_calls=matched, candidate_addresses=len(candidates),
                scope='sample_shift=0 fixed-lifetime fixture; no general lifetime or cache-line contention proof')
