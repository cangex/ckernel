# SPDX-License-Identifier: GPL-2.0
"""Request conservation under a native bio split, errors and pre-submit abort.

The independent fixture knows its original bio. The production request collector
does not acquire a parent-bio lifetime from that truth, nor infer a device owner.
"""
import re

CASES = {'plain': 0, 'split': 1, 'cancel': 2, 'error': 3}


def case_order():
    return [f'{case}-{mode}-r{r}' for r in range(1, 4) for case in CASES
            for mode in (('off', 'block') if r % 2 else ('block', 'off'))]


def check_case(case, window, logs, report=None, identities=None):
    scenario = CASES[case]; defects = []; used = set(); total = 0
    count = 0 if scenario == 2 else 1 if scenario == 0 else 2
    for role, text in enumerate(logs):
        pids = re.findall(r'CIS_SESSION_CONTAINER host_pid=(\d+)', text)
        jobs = re.findall(r'CIS_LIFECYCLE_JOB role=(\d+) scenario=(\d+) begin_ns=(\d+) end_ns=(\d+) rc=(-?\d+) original_bio=(\d+) bytes=(\d+) requests=(\d+) completed=(\d+) io_errors=(\d+) canceled=(\d+) verified=(\d+)', text)
        truth = [list(map(int, v)) for v in re.findall(r'CIS_LIFECYCLE_RQ request=(\d+) bio=(\d+) begin_ns=(\d+) end_ns=(\d+) sector=(\d+) bytes=(\d+) status=(\d+)', text)]
        if len(pids) != 1 or len(jobs) != 1:
            defects.append('job_protocol'); continue
        who, scen, lo, hi, rc, parent, size, requests, completed, errors, canceled, verified = map(int, jobs[0])
        if (who != role or scen != scenario or rc or not parent or size != (4096 if scenario == 0 else 8192)
                or requests != count or len(truth) != count or completed != (scenario != 2)
                or errors != (scenario == 3) or canceled != (scenario == 2) or verified != 1
                or not window['start_ns'] <= lo < hi <= window['end_ns']):
            defects.append('job_truth'); continue
        if (sum(t[5] for t in truth) != count * 4096 or
                sorted(t[4] for t in truth) != [(1 + role * 32) * 8 + n * 8 for n in range(count)]):
            defects.append('byte_or_sector_conservation')
        if count == 2 and (len({t[1] for t in truth}) != 2 or parent not in {t[1] for t in truth}):
            defects.append('independent_split_truth')
        total += count
        for address, bio, begin, end, sector, nbytes, status in truth:
            if not address or not bio or not lo <= begin < end <= hi or nbytes != 4096 or bool(status) != (scenario == 3):
                defects.append('driver_truth')
            if report is None: continue
            owner = [identities[role]['id'], identities[role]['generation']]
            tid = (int(pids[0]) << 32) | int(pids[0])
            matches = [r for r in report['requests'] if r['request'] == address and lo <= r['episode_ns'] < begin
                       and r['submitter'][:3] == owner + [tid] and r['episode_interval_ns'][1] is not None
                       and end <= r['episode_interval_ns'][1] <= hi]
            if len(matches) != 1:
                defects.append('request_truth_missing'); continue
            row = matches[0]; key = (row['request'], row['episode_ns']); used.add(key)
            if (row['terminal'] != 'data_completion' or row['initial_bio'] != bio or row['initial_bytes'] != nbytes
                    or row['operation'] & 255 != 1 or row['queue_intervals_ns'] and any(a > b for a,b in row['queue_intervals_ns'])
                    or sum(c['bytes'] for c in row['completions']) != nbytes or
                    any(c['status'] != status for c in row['completions']) or len(row['service_intervals']) != 1
                    or not begin <= row['service_intervals'][0]['interval_ns'][0] <= end or row['uncertainty']):
                defects.append('request_lifetime')
            origins = row.get('head_bio_origins', [])
            if not origins or any(v['registered_container'] != owner or v['ancestor_overdepth']
                                  or v['bytes'] != 4096 for v in origins):
                defects.append('bio_billing_identity')
    if report is not None:
        if report['quality']['status'] != 'PASS' or report['scope_audit']['status'] != 'PASS': defects.append('quality')
        if len(used) != len(report['requests']) or len(used) != total: defects.append('unexpected_or_duplicate_request')
        if any(r['blocking_container'] is not None for r in report['requests']): defects.append('false_blocker')
    return dict(status='FAIL' if defects else 'PASS', errors=sorted(set(defects)), driver_requests=total,
                request_bytes=total*4096, canceled_before_submit=scenario == 2,
                parent_bio_relation='FIXTURE_TRUTH_ONLY_NOT_PRODUCTION_ATTRIBUTION',
                scope='native split child requests and error completion; pre-submit cancellation is not in-flight cancellation')


def check_counters(case, before, after, result):
    delta = {k:after[k]-before[k] for k in before}
    expected = dict(requests=result['driver_requests'], completions=result['driver_requests'], requeues=0, partials=0,
                    errors=result['driver_requests'] if case == 'error' else 0)
    return dict(status='PASS' if delta == expected else 'FAIL', delta=delta, expected=expected)
