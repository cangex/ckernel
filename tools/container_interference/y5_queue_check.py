# SPDX-License-Identifier: GPL-2.0
"""Y5 private-flow truth, separate from sampled resource evidence."""
import argparse
import json
from pathlib import Path
from owner_report import fields
from queue_report import analyze
from source_switches import validate
from prototype_admission import SOURCE_KEYS

CASES={
    'sharedDirect':dict(destinations=[0,0],forwarded=False,actors=[0,1]),
    'separateDirect':dict(destinations=[0,1],forwarded=False,actors=[0]),
    'sharedForward':dict(destinations=[0,0],forwarded=True,actors=[]),
    'unselected':dict(destinations=[1,1],forwarded=False,actors=[]),
}


def order():
    return [dict(label='%sR%d%s'%(case,r,'On' if enabled else 'Off'),case=case,round=r,enabled=enabled)
            for r in range(1,4) for case in CASES for enabled in ((False,True) if r%2 else (True,False))]


def native_totals(text):
    rows=text.splitlines()
    if not rows or not rows[0].startswith('version=1 '): raise ValueError('native queue audit version')
    result=dict.fromkeys(('entries','filtered','sampled','emitted','expired','recursive'),0); seen=set()
    for line in rows[1:]:
        d=fields(line)
        if (set(d)!=set(result)|{'cpu'} or any(type(v) is not int or v<0 for v in d.values()) or
                not 0<=d['cpu']<512 or d['cpu'] in seen): raise ValueError('native queue audit schema')
        seen.add(d['cpu'])
        for k in result: result[k]+=d[k]
    if not seen: raise ValueError('empty source audit')
    return result


def source_delta(before,after):
    a,b=native_totals(before),native_totals(after)
    if any(b[k]<a[k] for k in a): raise ValueError('native audit decreased')
    return {k:b[k]-a[k] for k in a}


def check(case,window,logs,sinks,report=None,identities=None):
    errors=[]; actors=[]
    for i,log in enumerate(logs):
        lines=[l for l in log.splitlines() if l.startswith('CIS_QUEUE_WORK ')]
        if len(lines)!=1: errors.append('sender_record'); continue
        d=fields(lines[0]); actors.append(d)
        if (d.get('actor')!=i or d.get('sent')!=1000 or d.get('errors')!=0 or d.get('pid')!=1 or
                not window['start_ns']<=d.get('first',-1)<d.get('last',-1)<window['end_ns']): errors.append('sender_correctness_or_window')
    if len(actors)==2:
        for key in ('pidns','mntns'):
            if actors[0].get(key)==actors[1].get(key): errors.append('container_isolation')
        if CASES[case]['forwarded'] and actors[0].get('netns')==actors[1].get('netns'): errors.append('private_netns')
    delivered=[0,0]
    if len(sinks)!=2: errors.append('sink_count')
    else:
        for disk,s in enumerate(sinks):
            if s.get('invalid') or s.get('duplicate'): errors.append('payload_or_duplicate')
            for i in range(2):
                n=s.get('received',[0,0])[i]; delivered[i]+=n
                if n and disk!=CASES[case]['destinations'][i]: errors.append('cross_destination')
        if any(not 0<n<=1000 for n in delivered): errors.append('no_valid_delivery')
    counts=None
    if report is not None:
        if report['quality']['status']!='PASS': errors.append('capture_quality')
        counts=report['coverage']
        roots={tuple((v['id'],v['generation'])) for v in identities or []}
        observed={tuple(s['actor']) for s in report['samples'] if s['actor'] is not None}
        billed={tuple(s['socket_accounting']) for s in report['samples'] if s['socket_accounting'] is not None}
        expected={tuple((identities[i]['id'],identities[i]['generation'])) for i in CASES[case]['actors']}
        if case=='unselected':
            if report['samples'] or report['shared_resources']: errors.append('unselected_queue_admitted')
        else:
            if not counts['admission_samples'] or not counts['service_samples'] or not counts['backlog_samples']:
                errors.append('queue_coverage')
            if case=='sharedForward':
                if observed or billed or report['shared_resources']: errors.append('forwarded_origin_invented')
                if not counts['unknown_executors'] or not counts['unknown_socket_accounting']: errors.append('unknown_dropped')
            else:
                if observed!=expected or billed!=expected: errors.append('direct_participants')
                if case=='sharedDirect' and not report['shared_resources']: errors.append('shared_queue_not_found')
                if case=='separateDirect' and report['shared_resources']: errors.append('private_queue_false_sharing')
        if observed-roots or billed-roots: errors.append('unregistered_identity')
        if any(s['holder'] is not None or s['blocking_container'] is not None or s['packet_owner'] is not None for s in report['samples']):
            errors.append('invented_blocker')
    return dict(status='FAIL' if errors else 'PASS_SCOPED',errors=errors,senders=actors,
                delivered=delivered,undelivered=[1000-x for x in delivered],coverage=counts,
                scope='UDP private flows, shaped queue participation; not throughput or unique blocker acceptance')


def replay(serial,output):
    from session_check import extract
    if serial.stat().st_size>32<<20: raise ValueError('serial capacity')
    text=serial.read_text(); files=extract(text); out=Path(output); out.mkdir(exist_ok=False)
    prefix='/tmp/y5-queue-evidence/'
    def value(path): return json.JSONDecoder().raw_decode(files[prefix+path].lstrip())[0]
    result=value('result.json'); plan=value('plan.json'); permit=value('permit.json'); states=result['states']
    errors=[]; receipts=[]
    if ('CIS_PROFILE_VM_EXIT=0' not in text.splitlines() or
            'CIS_QUEUE_DEVICE_UNLOAD=0' not in text.splitlines()): errors.append('exit_or_unload')
    if any(s in text for s in ('BUG: KASAN:','Oops:','Kernel panic','WARNING: CPU:')): errors.append('kernel_warning')
    if plan.get('order')!=order() or plan.get('cases')!=CASES: errors.append('plan_changed')
    if any(result['source'].get(k)!=permit['source'].get(k) or plan['source'].get(k)!=permit['source'].get(k) for k in SOURCE_KEYS):
        errors.append('source_binding')
    if [{k:e[k] for k in ('label','case','round','enabled')} for e in states]!=order(): errors.append('fixed_order')
    for e in states:
        label=e['label']; report=None; identities=None
        if e['session_id']:
            sid=e['session_id']; record=value('records/'+sid+'.json')
            report=analyze(record,(files[prefix+'records/'+sid+'.jsonl'].rstrip()+'\n').encode())
            identities=[record['root_identities'][t] for t in e['targets']]
            if record['window']!=e['window']: errors.append(label+':window')
            if record['nonce']!=label or any(record.get(k)!=permit['source'].get(k) for k in SOURCE_KEYS):
                errors.append(label+':source_binding')
        checked=check(e['case'],e['window'],[files[prefix+label+'-%d.log'%i] for i in range(2)],
            [value(label+'-sink%d.json'%i) for i in range(2)],report,identities)
        if checked['status']!='PASS_SCOPED' or e['exit_codes']!=[0,0]: errors.append(label+':'+str(checked['errors']))
        validate(e['active_sources'],'qdisc' if e['enabled'] else None,e['before']['before_ns'],e['after']['after_ns'])
        validate(e['idle_sources'],None,e['before']['before_ns'],e['after']['after_ns'])
        delta=source_delta(e['before']['native'],e['after']['native'])
        if not e['enabled'] and any(delta.values()): errors.append(label+':off_callbacks')
        if e['enabled'] and (not delta['entries'] or delta['recursive']): errors.append(label+':native_entries_or_recursion')
        if e['enabled'] and e['case']=='unselected' and (not delta['filtered'] or delta['emitted']):
            errors.append(label+':native_unselected_filter')
        receipts.append(dict(label=label,checked=checked))
    receipt=dict(status='FAIL' if errors else 'PASS_SCOPED',errors=errors,states=receipts)
    (out/'replay.json').write_text(json.dumps(receipt,indent=2)); print(json.dumps(dict(status=receipt['status'],errors=errors)))
    return bool(errors)


if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('serial',type=Path); p.add_argument('output')
    a=p.parse_args(); raise SystemExit(replay(a.serial,a.output))
