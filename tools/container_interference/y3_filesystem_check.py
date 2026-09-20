# SPDX-License-Identifier: GPL-2.0
"""Functional private-directory truth; not a workload performance certificate."""
from owner_report import fields

CASES={'shared':dict(disks=[0,0],selected=0),
       'separate':dict(disks=[0,1],selected=0),
       'unselected':dict(disks=[1,1],selected=0),
       'orphanfile':dict(disks=[1,1],selected=1)}


def case_order():
    return [dict(case=c,round=r,enabled=v,label=c+str(r)+('on' if v else 'off'))
            for r in range(3) for c in CASES for v in ((False,True) if r%2==0 else (True,False))]


def check_case(case,window,logs,report=None,identities=None):
    errors=[]; actors=[]
    for role,log in enumerate(logs):
        rows=[fields(line) for line in log.splitlines() if line.startswith('CIS_FILESYSTEM_DONE ')]
        if len(rows)!=1: errors.append('workload_receipt'); continue
        d=rows[0]; actors.append(d)
        if (d.get('role')!=role or d.get('iterations')!=96 or d.get('bytes_per_file')!=65536 or d.get('errors')!=0 or
                not window['start_ns']<=d.get('begin_ns',0)<d.get('end_ns',2**64)<window['end_ns']):
            errors.append('workload_window_or_correctness')
    if len(actors)==2:
        a,b=actors
        if (a['major'],a['minor'],a['directory_inode'])==(b['major'],b['minor'],b['directory_inode']):
            errors.append('shared_directory_not_private')
        same=(a['major'],a['minor'])==(b['major'],b['minor'])
        if same!=(case!='separate'): errors.append('filesystem_layout')
    if report is not None:
        if report['quality']['status']!='PASS' or report['scope_audit']['status']!='PASS': errors.append('collector_quality')
        seen={tuple(e['actor'][:2]) for e in report['episodes']}
        expected=set() if case=='unselected' else {tuple(identities[0][k] for k in ('id','generation'))}
        if case in ('shared','orphanfile'): expected.add(tuple(identities[1][k] for k in ('id','generation')))
        if seen!=expected: errors.append('selection_or_missing_actor')
        counts=report['coverage']['operations']
        if case!='unselected':
            if not counts['allocation_group_use']: errors.append('missing_native_allocation')
            if not report['coverage']['waits']: errors.append('missing_native_journal_wait')
            if case=='orphanfile':
                if not counts['orphan_file_operation'] or counts['legacy_orphan_add'] or counts['legacy_orphan_delete']:
                    errors.append('orphan_feature_mismatch')
            elif not counts['legacy_orphan_add'] or not counts['legacy_orphan_delete'] or counts['orphan_file_operation']:
                errors.append('legacy_feature_mismatch')
        if case in ('separate','unselected') and report['shared_resources']: errors.append('false_sharing')
        if case in ('shared','orphanfile') and not report['shared_resources']: errors.append('missing_public_resource_sharing')
        if any(e['holder'] is not None or e['blocking_container'] is not None for e in report['episodes']):
            errors.append('invented_holder')
    return dict(status='FAIL' if errors else 'PASS',errors=errors,actors=actors)
