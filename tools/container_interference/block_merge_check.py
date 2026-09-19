# SPDX-License-Identifier: GPL-2.0
"""Independent driver truth: native bios actually passed through merge/dispatch."""
import re

CASES = {'back': (2, 0), 'front': (2, 2), 'gap': (2, 1), 'cap': (9, 0)}
SCHEDULER_CASES = {'bridge': (3, 3), 'gap': (2, 1)}


def case_order(scheduler=False):
    return [f'{case}-{mode}-r{round_}' for round_ in range(1,4) for case in (SCHEDULER_CASES if scheduler else CASES)
            for mode in (('off','block') if round_%2 else ('block','off'))]


def check_case(case, window, logs, report=None, identities=None):
    errors=[]; used=set(); total=0; count,pattern={**CASES,**SCHEDULER_CASES}[case]; expected_requests=count if case=='gap' else 1
    for role,text in enumerate(logs):
        pids=re.findall(r'CIS_SESSION_CONTAINER host_pid=(\d+)',text)
        jobs=re.findall(r'CIS_MERGE_JOB role=(\d+) count=(\d+) pattern=(\d+) begin_ns=(\d+) end_ns=(\d+) rc=(-?\d+) requests=(\d+) completed=(\d+) errors=(\d+) verified=(\d+)',text)
        truth=[list(map(int,r)) for r in re.findall(r'CIS_MERGE_RQ request=(\d+) begin_ns=(\d+) end_ns=(\d+) bytes=(\d+) bios=(\d+)',text)]
        if len(pids)!=1 or len(jobs)!=1:
            errors.append('job_protocol'); continue
        who,n,pattern_,lo,hi,rc,requests,completed,bad,verified=map(int,jobs[0]); pid=int(pids[0])
        if (who!=role or n!=count or pattern_!=pattern or rc or bad or verified!=1 or completed!=count or
                requests!=expected_requests or len(truth)!=requests or
                not window['start_ns']<=lo<hi<=window['end_ns'] or
                sum(r[3] for r in truth)!=count*4096 or sum(r[4] for r in truth)!=count):
            errors.append('job_truth'); continue
        total+=requests
        for address,begin,end,size,bios in truth:
            if not lo<=begin<end<=hi or size!=bios*4096 or bios!=(1 if case=='gap' else count):
                errors.append('driver_truth')
            if report is None: continue
            ident=identities[role]; owner=[ident['id'],ident['generation']]
            matches=[r for r in report['requests'] if r['request']==address and lo<=r['episode_ns']<begin
                     and r['submitter'][:3]==owner+[(pid<<32)|pid]]
            if len(matches)!=1: errors.append('driver_request_missing'); continue
            r=matches[0]; key=(r['request'],r['episode_ns']); used.add(key)
            if (r['terminal']!='data_completion' or not end<=r['episode_interval_ns'][1]<=hi or
                    sum(c['bytes'] for c in r['completions'])!=size or any(c['status'] for c in r['completions']) or
                    len(r['service_intervals'])!=1 or not begin<=r['service_intervals'][0]['interval_ns'][0]<=end):
                errors.append('request_lifetime')
            p=report['provenance']; snaps=[s for s in p['issue_sources'] if (s['request'],s['episode_ns'])==key]
            links=[l for l in p['merge_transfers'] if l['survivor']==list(key)]
            if case=='bridge':
                family={key}
                for unused in range(3):
                    for link in p['merge_transfers']:
                        if tuple(link['survivor']) in family and link['victim']:
                            family.add(tuple(link['victim']))
                links=[l for l in p['merge_transfers'] if tuple(l['survivor']) in family]
                victims=[v for v in report['requests'] if (v['request'],v['episode_ns']) in family-{key}]
                if (len(family)!=2 or len(victims)!=1 or victims[0]['terminal']!='merge_transfer' or
                        victims[0]['submitter'][:3]!=owner+[(pid<<32)|pid] or
                        not lo<=victims[0]['episode_ns']<begin or
                        victims[0].get('merge_survivor')!=list(key)):
                    errors.append('scheduler_victim_truth')
                used.update(family)
            expected_unknown=max(0,bios-8)*4096
            if (len(snaps)!=1 or snaps[0]['remaining_bytes']!=size or snaps[0]['unknown_bytes']!=expected_unknown or
                    snaps[0]['observed_bios']!=min(bios,8) or snaps[0]['truncated']!=(bios>8) or
                    snaps[0]['sources']!=[dict(container=owner,bytes=size-expected_unknown,fraction=(size-expected_unknown)/size)]):
                errors.append('bio_weights')
            if case=='bridge':
                if (len(links)!=2 or len([l for l in links if l['kind']==1 and l['state']=='OBSERVED_TRANSFER'])!=1 or
                        len([l for l in links if l['kind'] in (2,3) and l['state']=='BIO_APPEND' and l['transferred_bytes']==4096])!=1):
                    errors.append('scheduler_native_links')
            elif (len(links)!=bios-1 or any(l['state']!='BIO_APPEND' or l['kind']!=(3 if case=='front' else 2)
                                         or l['transferred_bytes']!=4096 for l in links)):
                errors.append('native_merge_links')
    if report is not None:
        if report['quality']['status']!='PASS' or report['scope_audit']['status']!='PASS': errors.append('quality')
        if len(used)!=len(report['requests']) or len(used)!=total*(2 if case=='bridge' else 1): errors.append('population')
        if any(r['blocking_container'] is not None for r in report['requests']): errors.append('false_blocker')
    return dict(status='FAIL' if errors else 'PASS',errors=sorted(set(errors)),driver_requests=total,
                bytes=2*count*4096,scope='native bio merge and dispatch, not cross-container causal blocking')


def check_counters(before,after,result):
    delta={k:after[k]-before[k] for k in before}
    expected=dict(requests=result['driver_requests'],completions=result['driver_requests'],requeues=0,partials=0,errors=0)
    return dict(status='PASS' if delta==expected else 'FAIL',delta=delta,expected=expected)
