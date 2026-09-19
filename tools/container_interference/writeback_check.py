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
    background=[]; selected=set(); all_requests=[]; billed_bytes={}; inode_links=0; dirty_actors=set()
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
                interval=req['episode_interval_ns']
                if len(writers)!=2 or not min(v['begin_ns'] for v in writers)<=interval[0]<=interval[1]<=sync_interval[1]:
                    errors.append('background_truth_interval')
                if any(c['status'] for c in req['completions']): errors.append('background_io_error')
                billed_bytes[source]=billed_bytes.get(source,0)+sum(c['bytes'] for c in req['completions'])
        if not background: errors.append('no_real_background_writeback')
        if case=='private' and selected!=expected: errors.append('private_billing_coverage')
        if sum(billed_bytes.values())!=262144 or case=='private' and any(billed_bytes.get(k)!=131072 for k in expected):
            errors.append('buffered_data_byte_coverage')
        wb=report.get('writeback',{})
        if wb.get('coverage')=='AVAILABLE':
            links={tuple(v['request']):v['context'] for v in wb['request_links']}
            for req in background:
                ctx=links.get((req['request'],req['episode_ns']))
                if not ctx or ctx['exclusive_dirtier'] is not None or ctx['blocking_container'] is not None:
                    errors.append('missing_or_invented_inode_context'); continue
                matching=[(i,w) for i,w in enumerate(writers) if
                    (w['major'],w['minor'],w['inode'])==(*ctx['device'],ctx['ino'])]
                if not matching or ctx['executor']!=req['submitter']:
                    errors.append('wrong_inode_context'); continue
                if case=='private' and tuple(req['selected_container'])!=tuple(identities[matching[0][0]][k] for k in ('id','generation')):
                    errors.append('private_inode_billing_mismatch')
                inode_links+=1
            for i,w in enumerate(writers):
                who=tuple(identities[i][k] for k in ('id','generation'))
                found=[d for d in wb['dirty_observations'] if tuple(d['actor'][:2])==who and
                       (d['device'][0],d['device'][1],d['ino'])==(w['major'],w['minor'],w['inode']) and
                       w['begin_ns']<=d['time_ns']<=w['end_ns']]
                if not found: errors.append('dirty_transition_missing_'+str(i))
                else: dirty_actors.add(who)
            if inode_links!=len(background): errors.append('inode_request_coverage')
        # Two writers of the shared inode need not appear as two blkcg owners.
        # That native writeback choice is exactly why we never infer dirtier.
    return dict(status='FAIL' if errors else 'PASS',errors=errors,writers=writers,
        background_requests=len(background),requests=len(all_requests),selected_billing_roots=[list(v) for v in sorted(selected)],
        billed_completed_bytes=[dict(container=list(k),bytes=v) for k,v in sorted(billed_bytes.items())],
        dirty_transition_actors=[list(k) for k in sorted(dirty_actors)],inode_request_links=inode_links,
        dirtying_actor_link='OBSERVED_TRANSITIONS_NOT_EXCLUSIVE_OWNER' if dirty_actors else 'UNOBSERVED',
        inode_request_link='CLOSED_NATIVE_CONTEXT' if inode_links else 'UNOBSERVED',blocking_container=None,
        scope='buffered writes and native background bio billing, not per-inode or causal attribution')
