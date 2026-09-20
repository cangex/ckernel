# SPDX-License-Identifier: GPL-2.0
"""Frozen Y7 independent-socket cohort and replay, not unique-blocker proof."""
import json
from pathlib import Path
import sys
from owner_report import fields
from prototype_admission import SOURCE_KEYS
from session_check import extract
from source_switches import validate
from unified_report import analyze
from y5_queue_check import source_delta
from y7_private_check import order, ROLES, cost_fields

def captures(mode):
    if mode not in ('off','survey','profile'): raise ValueError('capture mode')
    return () if mode=='off' else ('ip',) if mode=='survey' else ('ip','qdisc','cpu')

def validate_plan(plan):
    arrangement=plan.get('arrangement')
    if (plan.get('schema')!='cis-y7-queue-plan-v1' or arrangement not in ('shared','separate') or
            plan.get('order')!=order() or plan.get('cpus')!=[0,0,1,1] or
            plan.get('destinations')!=([0]*4 if arrangement=='shared' else [0,1,0,1]) or
            plan.get('management_cpu')!=7 or plan.get('rounds')!=3 or plan.get('window_ms')!=2000 or
            plan.get('offered')!=4500 or plan.get('period_ns')!=2_000_000 or
            plan.get('timeout_ns')!=100_000_000 or plan.get('payload_bytes')!=1024 or
            plan.get('egress_rate')!='100mbit' or plan.get('tx_queue')!=0 or
            type(plan.get('selected_ifindex')) is not int or plan['selected_ifindex']<=0):
        raise ValueError('unexpected frozen network plan')

def workload(client,server,actor):
    c=[fields(l.split(' ',1)[1]) for l in client.splitlines() if l.startswith('Y7_QUEUE_CLIENT ')]
    s=[fields(l.split(' ',1)[1]) for l in server.splitlines() if l.startswith('Y7_QUEUE_SERVER ')]
    samples=[l.split(' ',1)[1] for l in client.splitlines() if l.startswith('Y7_QUEUE_LATENCIES ')]
    if len(c)!=1 or len(s)!=1 or len(samples)!=1: raise ValueError('both endpoint terminals required')
    c,s=c[0],s[0];v=[int(n) for n in samples[0].split(',')]
    if (set(c)!=set('actor due begin end offered completed errors timeouts period timeout p99 max sum pidns mntns netns'.split()) or
            set(s)!=set('actor received errors duplicates pidns mntns netns'.split()) or c['actor']!=actor or s['actor']!=actor or
            c['offered']!=4500 or c['completed']!=4500 or s['received']!=4500 or
            c['errors'] or s['errors'] or s['duplicates'] or c['period']!=2_000_000 or c['timeout']!=100_000_000 or
            not c['due']<=c['begin']<c['end'] or len(v)!=4500 or v!=sorted(v) or min(v)<0 or
            c['p99']!=v[4454] or c['max']!=v[-1] or c['sum']!=sum(v) or
            c['timeouts']!=sum(n>c['timeout'] for n in v)):
        raise ValueError('queue payload, delivery or arrival-relative timing failed')
    if any(type(w[k]) is not int or w[k]<=0 for w in (c,s) for k in ('pidns','mntns','netns')):
        raise ValueError('namespace identity')
    return dict(c,server=s,throughput=4500e9/(c['end']-c['due']),
        timing='scheduled arrival through validated echo; serialization backlog included',
        population='fixed offered sequence, not saturated throughput')

def validate_namespaces(work,plan):
    for key in ('pidns','mntns'):
        if len({w[key] for w in work}|{w['server'][key] for w in work})!=8:
            raise ValueError('endpoint containers are not independent')
    clients={w['netns'] for w in work};servers={w['server']['netns'] for w in work}
    if len(clients)!=1 or clients & servers: raise ValueError('network namespace placement')
    for i,a in enumerate(work):
        for j,b in enumerate(work[i+1:],i+1):
            if (a['server']['netns']==b['server']['netns'])!=(plan['destinations'][i]==plan['destinations'][j]):
                raise ValueError('server network namespace placement')

def check(state,clients,servers,records,raws,plan):
    errors=[]; observations=[]
    if len(clients)!=4 or len(servers)!=4 or len(set(state['all_targets']))!=4:
        raise ValueError('four independent actors required')
    work=[workload(c,s,i) for i,(c,s) in enumerate(zip(clients,servers))]
    validate_namespaces(work,plan)
    selected=[state['all_targets'][i] for i in ROLES[state['round']]]
    if state['targets']!=selected or state['exit_codes']!=[0]*8: errors.append('roles_or_exit')
    if any(w['due']!=state['start_ns'] for w in work): errors.append('business_binding')
    expected=captures(state['mode'])
    if len(records)!=len(expected) or len(raws)!=len(expected) or len(state['sessions'])!=len(expected):
        raise ValueError('capture population')
    for i,(collector,record,raw) in enumerate(zip(expected,records,raws)):
        observation=state['sessions'][i];window=record['window']
        if (record['collector']!=collector or record['targets']!=selected or
                str(record['session_id'])!=str(observation['session_id']) or
                any(record.get(k)!=plan['source'][k] for k in SOURCE_KEYS)):
            errors.append('source_or_capture_binding')
        if not max(w['begin'] for w in work)<window['start_ns']<window['end_ns']<min(w['end'] for w in work):
            errors.append('business_window_coverage')
        report=analyze(record,raw)
        if report['quality']['status']!='PASS' or not record.get('objects_absent'): errors.append('quality_or_cleanup')
        validate(observation['active_sources'],collector,record['receipt']['prepared_ns'],window['end_ns'])
        # A budget stop may detach before the planned window end. Audit that
        # real stop, but still reject its PARTIAL capture above.
        validate(observation['idle_sources'],None,record['receipt']['producers_stopped_ns'],2**64-1)
        if any(r['causal']!='NOT_ESTABLISHED' for r in report['relations']): errors.append('causal_overclaim')
        if collector=='qdisc':
            q=report['specialist'];observed={tuple(s['actor']) for s in q['samples'] if s['actor'] is not None}
            identities=dict(record.get('owner_identities',{}));identities.update(record['root_identities'])
            allowed={(identities[state['all_targets'][j]]['id'],identities[state['all_targets'][j]]['generation'])
                for j in range(4) if plan['destinations'][j]==0}
            if observed!=allowed: errors.append('queue_participant_binding')
            if len(allowed)<2 and q['shared_resources']: errors.append('separate_queue_false_sharing')
            if any(s['holder'] is not None or s['blocking_container'] is not None or s['packet_owner'] is not None for s in q['samples']):
                errors.append('invented_blocker')
        observations.append(dict(collector=collector,quality=report['quality'],relations=report['relations'],
            omitted=report.get('omitted_relations'),process_cpu=record.get('process_cpu_budget'),rss_bytes=record.get('combined_rss_peak_bytes'),
            raw_sha256=report['raw_sha256'],analysis_source_sha256=report['analysis_source_sha256'],
            coverage=(report.get('specialist') or {}).get('coverage'),report_timing=report.get('timing')))
        del report
    validate(state['idle_sources'],None,0,2**64-1)
    delta=source_delta(state['before']['queue_audit'],state['after']['queue_audit'])
    if state['mode']!='profile' and any(delta.values()): errors.append('queue_callbacks_outside_profile')
    if state['mode']=='profile' and (not delta['entries'] or delta['recursive']): errors.append('queue_entries_or_recursion')
    measured=cost_fields(state,plan)
    if any(a['memory_events_delta'].get('oom',0) or a['memory_events_delta'].get('oom_kill',0) for a in measured['system_cost']['actors']):
        errors.append('business_oom')
    return dict(status='FAIL' if errors else 'PASS_SCOPED',errors=sorted(set(errors)),workloads=work,
        **measured,observations=observations,queue_audit_delta=delta)

def replay(serial,destination):
    text=Path(serial).read_text();files=extract(text);prefix='/tmp/y7-queue-evidence/'
    def value(n): return json.JSONDecoder().raw_decode(files[prefix+n].lstrip())[0]
    plan=value('plan.json');declared=value('result.json');permit=value('permit.json');validate_plan(plan)
    if (declared['states']!=[dict(label=v['label'],result='PASS_SCOPED') for v in order()] or
            any(plan['source'][k]!=permit['source'][k] for k in SOURCE_KEYS)):
        raise ValueError('matrix or source binding')
    if 'CIS_PROFILE_VM_EXIT=0' not in text.splitlines() or 'CIS_QUEUE_DEVICE_UNLOAD=0' not in text.splitlines():
        raise ValueError('guest failed or module not unloaded')
    if any(s in text for s in ('Oops:','Kernel panic','BUG: KASAN:','WARNING: CPU:')): raise ValueError('kernel failure')
    out=Path(destination);out.mkdir(mode=0o700);states=[]
    for entry in order():
        label=entry['label'];s=value(label+'-evidence.json')
        if any(s[k]!=entry[k] for k in entry): raise ValueError('state binding')
        records=[value('records/'+v['session_id']+'.json') for v in s['sessions']]
        raws=[(files[prefix+'records/'+v['session_id']+'.jsonl'].rstrip()+'\n').encode() for v in s['sessions']]
        checked=check(s,[files[prefix+label+'-client%d.log'%i] for i in range(4)],
            [files[prefix+label+'-server%d.log'%i] for i in range(4)],records,raws,plan)
        (out/(label+'-check.json')).write_text(json.dumps(checked,indent=2))
        if checked['status']!='PASS_SCOPED': raise ValueError(checked['errors'])
        states.append(dict(**entry,**checked))
    comparisons=[]
    for r in range(3):
        off=next(s for s in states if s['round']==r and s['mode']=='off')
        for s in (s for s in states if s['round']==r and s['mode']!='off'):
            for i,(a,b) in enumerate(zip(off['workloads'],s['workloads'])):
                comparisons.append(dict(round=r,mode=s['mode'],actor=i,role='target' if i in ROLES[r] else 'bystander',
                    p99_delta_ns=b['p99']-a['p99'],p99_change=b['p99']/a['p99']-1 if a['p99'] else None,
                    throughput_change=b['throughput']/a['throughput']-1,timeouts_before=a['timeouts'],timeouts_after=b['timeouts']))
    receipt=dict(status='PASS_SCOPED',cohort='private_connections',arrangement=plan['arrangement'],
        states=states,comparisons=comparisons,source=plan['source'],y7_complete=False,
        limits=['fixed offered rate, not saturated throughput','P99 record-only','shared host network namespace, private sockets',
            'four accounting roots, eight endpoint containers','queue participation not unique blocking container',
            'whole-VM and management costs are not observer-exclusive'])
    (out/'verification.json').write_text(json.dumps(receipt,indent=2))
    return dict(status=receipt['status'],states=len(states),captures=sum(len(s['observations']) for s in states))

if __name__=='__main__': print(json.dumps(replay(*sys.argv[1:])))
