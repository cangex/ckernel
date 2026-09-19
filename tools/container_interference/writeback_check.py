# SPDX-License-Identifier: GPL-2.0
"""Buffered ext4 truth is not reconstructed from Profile request records."""
from owner_report import fields


def case_order():
    return [f'{case}-{mode}-r{r}' for r in range(1,4) for case in ('private','shared')
            for mode in (('off','block') if r%2 else ('block','off'))]


def check_case(case, window, logs, sync_interval, verified, report=None, identities=None):
    errors=[]; writers=[]
    if case not in ('private','shared') or len(logs)!=2: raise ValueError('writeback case')
    for role,log in enumerate(logs):
        rows=[fields(line) for line in log.splitlines() if line.startswith('CIS_WRITEBACK_WRITE ')]
        if len(rows)!=1 or 'CIS_WRITEBACK_DONE errors=0' not in log.splitlines():
            errors.append('writer_truth_'+str(role)); continue
        r=rows[0]; writers.append(r)
        if (r.get('role')!=role or r.get('buffered')!=1 or r.get('bytes')!=131072 or
                r.get('offset')!=role*131072 or r.get('pattern')!=0x35+role or
                not r.get('inode') or not window['start_ns']<=r['begin_ns']<=r['end_ns']<sync_interval[0]):
            errors.append('writer_fields_'+str(role))
    if not window['start_ns']<sync_interval[0]<=sync_interval[1]<window['end_ns'] or verified!=[True,True]:
        errors.append('sync_or_persisted_bytes')
    if len(writers)==2:
        a,b=writers
        same=(a['major'],a['minor'],a['inode'])==(b['major'],b['minor'],b['inode'])
        if same!=(case=='shared'): errors.append('inode_truth')
    background=[]; selected=set(); all_requests=[]
    if report is not None:
        if report['quality']['status']!='PASS' or report['scope_audit']['status']!='PASS': errors.append('capture_quality')
        expected={(v['id'],v['generation']) for v in identities}
        devices={(v['major'],v['minor']) for v in writers}
        all_requests=report['requests']
        for req in all_requests:
            if (req.get('initial_dirtier') is not None or req.get('inode_owner') is not None or
                    req.get('blocking_container') is not None): errors.append('invented_owner')
            if req.get('admission')!='bio_billing_root': continue
            source=tuple(req['selected_container'])
            if source not in expected or req['submitter'][:2]!=[0,0]: errors.append('executor_renamed')
            if (req['submitter_kernel_thread'] and req['operation'] & 0xff == 1 and
                    set(map(tuple,req['devices'])) & devices and req['terminal']=='data_completion'):
                background.append(req); selected.add(source)
                if not any('wb_workfn' in f or 'writeback' in f for f in req['start_stack_leaf_to_root']):
                    errors.append('background_stack')
        if not background: errors.append('no_real_background_writeback')
        if case=='private' and selected!=expected: errors.append('private_billing_coverage')
        # Two writers of the shared inode need not appear as two blkcg owners.
        # That native writeback choice is exactly why we never infer dirtier.
    return dict(status='FAIL' if errors else 'PASS',errors=errors,writers=writers,
        background_requests=len(background),requests=len(all_requests),selected_billing_roots=[list(v) for v in sorted(selected)],
        dirtying_actor_link='UNOBSERVED',inode_request_link='UNOBSERVED',blocking_container=None,
        scope='buffered writes and native background bio billing, not per-inode or causal attribution')
