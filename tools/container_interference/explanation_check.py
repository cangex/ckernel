# SPDX-License-Identifier: GPL-2.0
"""Check every bounded owner edge against independently logged fixture truth."""
from owner_report import analyze, fields


def check_owner(events, workload_logs):
    truth=[];resets=[]
    for text in workload_logs:
        for line in text.splitlines():
            if line.startswith('CIS_TRUTH '):truth.append(fields(line))
            if line.startswith('CIS_RESET '):resets.append(fields(line)['time_ns'])
    report=analyze(events)
    bad_holder=bad_waiter=crossed=0
    observed=set()
    for edge in report['edges']:
        obj=int(edge['object'],16)
        def matches(role,begin_key,end_key):
            actor=edge[role]
            return [i for i,q in enumerate(truth) if q['object']==obj and
                    q['cgroup_id']==actor[0] and q['host_tid']==(actor[2]&0xffffffff) and
                    min(q[end_key],edge['end_ns'])>max(q[begin_key],edge['begin_ns'])]
        holders=matches('holder','acquired_ns','released_ns')
        waiters=matches('waiter','begin_ns','acquired_ns')
        bad_holder+=not holders;bad_waiter+=not waiters
        observed.update(waiters)
        crossed+=any(edge['begin_ns']<t<edge['end_ns'] for t in resets)
    return dict(edges=len(report['edges']),truth_operations=len(truth),
                truth_operations_with_observed_edge=len(observed),
                wrong_holder_intersections=bad_holder,wrong_waiter_intersections=bad_waiter,
                crossed_resets=crossed,directions=len({(tuple(e['holder'][:2]),tuple(e['waiter'][:2])) for e in report['edges']}),
                holder_offcpu_spans=sum(len(e['holder_offcpu']) for e in report['edges']),
                status='FAIL' if bad_holder or bad_waiter or crossed else 'PASS' if truth else 'BLOCKED',
                scope='fixture interval consistency only; not full-kernel recall or application causality')
