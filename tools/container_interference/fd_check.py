#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent fixture brackets, never a source of fabricated measured owners."""
import hashlib
import json


def check(report, logs, case):
    if case not in ('threads','private','native','cross','reuse'): raise ValueError('unsupported FD case')
    errors=[];truth=[];summaries=[]
    for text in logs:
        if len(text.encode())>1<<20: raise ValueError('truth log capacity')
        done=[json.loads(line.split(' ',1)[1]) for line in text.splitlines() if line.startswith('CIS_FD_DONE ')]
        if len(done)!=1 or done[0].get('failed') or done[0].get('operations_per_thread')!=16:
            errors.append('workload_incomplete')
        else: summaries+=done
        truth += [json.loads(line.split(' ',1)[1]) for line in text.splitlines() if line.startswith('CIS_FD_TRUTH ')]
    if len(logs)!=(8 if case=='reuse' else 2): errors.append('container_count')
    if report['quality']['status']!='PASS': errors.append('capture_quality')
    if report.get('omitted_findings',0): errors.append('omitted_relations_not_audited')
    if report.get('finding_count',len(report['findings']))!=len(report['findings']):
        errors.append('incomplete_relation_population')
    count=1 if case in ('private','cross') else 2
    if any(row['threads']!=count or row['native']!=int(case=='native') for row in summaries): errors.append('workload_configuration')
    if len(truth)!=(0 if case=='native' else 16*count*len(logs)): errors.append('truth_count')
    if case=='cross':
        shared=[json.loads(line.split(' ',1)[1]) for text in logs for line in text.splitlines()
                if line.startswith('CIS_FD_SHARED ')]
        if len(shared)!=2 or any(row.get('pidns_init')!=1 or row.get('error') or
                                 row.get('explicit_clone_files') is not True for row in shared):
            errors.append('shared_container_setup')
        if len({row['object'] for row in truth})!=1 or len({row['files'] for row in truth})!=1:
            errors.append('tables_not_shared')
        if len({row['cgroup_id'] for row in truth})!=2 or len({row['tgid'] for row in truth})!=2:
            errors.append('actors_not_distinct_containers')
    for row in truth:
        if not row['begin_ns']<=row['acquired_ns']<row['release_begin_ns']<=row['released_ns']:
            errors.append('truth_interval')
    edges=[row for row in report['findings'] if row.get('resource')=='files_struct_lock']
    matched=0
    for edge in edges:
        expected=('cross_container','different_tgid') if case=='cross' else ('container_internal','same_tgid')
        if (edge['relation'],edge['process_scope'])!=expected: errors.append('false_cross_container_or_process')
        if case=='native': continue
        def matching(actor):
            return [row for row in truth if row['tid']==(actor[2]&0xffffffff) and
                    row['tgid']==actor[2]>>32 and row['cgroup_id']==actor[0] and
                    row['object']==int(edge['object'],16)]
        holders,waiters=matching(edge['holder']),matching(edge['waiter'])
        pairs=[(h,w) for h in holders for w in waiters
               if w['begin_ns']<=edge['wait_begin_ns']<edge['wait_end_ns']<=w['acquired_ns']
               and h['begin_ns']<=edge['begin_ns']<edge['end_ns']<=h['released_ns']
               and max(h['acquired_ns'],w['begin_ns'])<min(h['release_begin_ns'],w['acquired_ns'])]
        if len(pairs)!=1: errors.append('owner_or_waiter_not_independently_bracketed')
        else: matched+=1
    if case in ('threads','cross','reuse') and not matched: errors.append('missing_positive')
    if case=='private' and edges: errors.append('private_false_positive')
    reused=0
    if case=='reuse':
        groups={}
        for row in truth:
            groups.setdefault((row['object'],row['tgid']),[]).append(row)
        objects={}
        for (obj,tgid),records in groups.items():
            objects.setdefault(obj,[]).append((min(r['begin_ns'] for r in records),max(r['released_ns'] for r in records),tgid))
        for lifetimes in objects.values():
            lifetimes.sort()
            for left,right in zip(lifetimes,lifetimes[1:]):
                if left[1]>=right[0]: errors.append('overlapping_reuse_truth')
                else: reused+=1
        if not reused: errors.append('address_reuse_not_observed')
    return dict(schema='cis-fd-truth-v1',status='FAIL' if errors else 'PASS',errors=sorted(set(errors)),
                measured_edges=len(edges),matched_edges=matched,truth_operations=len(truth),
                capture_quality=report['quality']['status'],
                observed_address_reuses=reused,
                truth_sha256=[hashlib.sha256(log.encode()).hexdigest() for log in logs],
                boundary='fixture validates identity and interval overlap, not population recall or performance',
                native_truth='not available; no fixture counts or recall inferred' if case=='native' else None)
