# SPDX-License-Identifier: GPL-2.0
"""Independent native queue/clone/close truth, not fabricated trace events."""
from owner_report import fields

CASES=('txplain','txclone')


def check(case,window,logs,report=None,identities=None):
    errors=[]; truth=[]; matched=[]
    if case not in CASES or len(logs)!=2: return dict(status='FAIL',errors=['case'])
    cloned=case=='txclone'
    for actor,log in enumerate(logs):
        rows=[fields(line[len('CIS_NET_RELEASE '):]) for line in log.splitlines() if line.startswith('CIS_NET_RELEASE ')]
        if len(rows)!=1: errors.append('truth_count'); continue
        r=rows[0]; truth.append(r)
        keys={'actor','cookie','clone','original','child','data_refs','header_refs','send_begin','send_end',
              'inspect_begin','inspect_end','close_begin','close_end','child_begin','child_end'}
        if set(r)!=keys or any(type(r[k]) is not int or r[k]<0 for k in keys):
            errors.append('truth_schema'); continue
        times=[window['start_ns']]+[r[k] for k in ('send_begin','send_end','inspect_begin','inspect_end','close_begin','close_end')]
        if cloned: times += [r['child_begin'],r['child_end']]
        times.append(window['end_ns'])
        if (r['actor']!=actor or r['clone']!=int(cloned) or not r['cookie'] or not r['original'] or
                times!=sorted(times) or bool(r['child'])!=cloned or r['child']==r['original'] or
                r['header_refs']!=(2 if cloned else 1) or r['data_refs'] & 65535 != (2 if cloned else 1)):
            errors.append('native_reference_or_order'); continue
        if report is None: continue
        identity=identities[actor]
        candidates=[e for e in report['tx']['episodes'] if e['skb_address']==r['original'] and
                    r['send_begin']<=e['begin_ns']<=e['backend_interval_ns'][1]<=r['send_end']]
        if len(candidates)!=1: errors.append('original_match'); continue
        e=candidates[0]; matched.append(e)
        interval=e.get('release_backend_interval_ns')
        if (e['requester'][:2]!=[identity['id'],identity['generation']] or e['cookie']!=r['cookie'] or
                e['outcome']!='ADMITTED' or e.get('release_backend_status')!='RETURNED' or not interval or
                not r['close_begin']<=e['release_entry_ns']<=interval[0]<=interval[1]<=r['close_end'] or
                e['data_release_status']!=('SHARED_REFERENCE_RETAINED' if cloned else 'BACKEND_RETURNED') or
                e['header_release_status']!=('FCLONE_PAIR_RETAINED' if cloned else 'BACKEND_RETURNED') or
                e['packet_payload_owner']!='UNKNOWN' or e['clone_lineage']!='UNOBSERVED' or
                e['blocking_container'] is not None):
            errors.append('release_provenance_or_backend')
        if cloned and any(e['skb_address']==r['child'] for e in report['tx']['episodes']):
            errors.append('fabricated_clone_owner')
    if len(truth)==2 and (truth[0].get('cookie')==truth[1].get('cookie') or
                         truth[0].get('original')==truth[1].get('original') and
                         max(truth[0]['send_begin'],truth[1]['send_begin'])<min(truth[0]['close_end'],truth[1]['close_end'])):
        errors.append('private_identity')
    if report and (report['quality']['status']!='PASS' or report['tx']['status']!='PASS' or
                   report['tx']['unknown'] or len(report['tx']['episodes'])!=2 or len(matched)!=2):
        errors.append('coverage_or_quality')
    return dict(status='FAIL' if errors else 'PASS',errors=errors,truth=truth,matched=len(matched),
                scope='native original header release backend, retained real clone negative; no payload owner or blocking relation')
