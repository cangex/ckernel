# SPDX-License-Identifier: GPL-2.0
"""Check an ordinary memory workload without pretending it is event truth."""
from owner_report import fields


def check(record, report, logs, identities):
    defects, actors = [], []
    for index, text in enumerate(logs):
        pids = [fields(line)['host_pid'] for line in text.splitlines()
                if line.startswith('CIS_SESSION_CONTAINER ')]
        ops = [fields(line) for line in text.splitlines() if line.startswith('CIS_MEM_OP ')]
        if (len(pids) != 1 or pids[0] <= 0 or len(ops) != 16 or
                [op.get('index') for op in ops] != list(range(16)) or
                any(op.get('success') != 1 or op.get('bytes') != 8 << 20 or
                    not record['window']['start_ns'] <= op.get('begin_ns', 0) <
                    op.get('end_ns', 0) <= record['window']['end_ns'] for op in ops)):
            defects.append('workload_'+str(index)); continue
        identity = identities[index]
        calls = [c for c in report['calls'] if c['actor'][:2] == [identity['id'], identity['generation']]
                 and c['actor'][2] & 0xffffffff == pids[0]
                 and any(op['begin_ns'] <= c['interval_ns'][0] < c['interval_ns'][1] <= op['end_ns'] for op in ops)]
        if not calls or any(c['sample_shift'] != 6 for c in calls):
            defects.append('sampled_calls_'+str(index))
        native = [c for c in calls if any('mem_cgroup' in s or 'memcg' in s for s in c['stack_leaf_to_root'])]
        if not native: defects.append('memcg_stack_'+str(index))
        actors.append(dict(container=[identity['id'], identity['generation']], host_pid=pids[0],
                           successful_operations=len(ops), selected_calls=len(calls), memcg_stack_calls=len(native),
                           sampled_call_wall_ns=[c['elapsed_wall_ns'] for c in calls],
                           operation_wall_ns=[op['end_ns']-op['begin_ns'] for op in ops]))
    if report['quality']['status'] != 'PASS': defects.append('capture_quality')
    return dict(status='FAIL' if defects else 'PASS', defects=defects, actors=actors,
                eligible_event_recall='UNAVAILABLE', native_object_lifetime='UNKNOWN',
                cacheline_contention='UNVERIFIED', causal_claim='NONE',
                scope='real container memory operations and sampled native memcg update paths; not counter event ground truth')
