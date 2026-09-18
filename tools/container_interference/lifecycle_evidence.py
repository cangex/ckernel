# SPDX-License-Identifier: GPL-2.0
"""Bounded crash cases: OS signal audit, status transitions and durable records."""
import json

CASES = {'workerCrash': [('worker',9)], 'workerStop': [('worker',19)],
         'controllerStop': [('controller',19),('controller',18)],
         'controllerCrash': [('controller',9)], 'bothCrash': [('worker',9),('controller',9)]}


def analyze(files, records, clean_exit):
    streams=[body for name,body in files.items() if name.endswith('/fault-actions.jsonl')]
    if not streams:return dict(status='BLOCKED',reason='raw OS/control fault actions missing')
    if len(streams)!=1:raise ValueError('one fault action stream required')
    actions=[json.loads(x) for x in streams[0].splitlines() if x.startswith('{')]
    previous=-1
    for seq,row in enumerate(actions,1):
        if row['sequence']!=seq or row['before_ns']<previous or row['after_ns']<row['before_ns']:
            raise ValueError('unordered fault actions')
        previous=row['after_ns']
    by_nonce={r['nonce']:r for r in records.values()}
    results={}
    for nonce,expected in CASES.items():
        record=by_nonce.get(nonce)
        if record is None:
            results[nonce]=dict(status='BLOCKED',reason='durable record missing');continue
        sid=str(record['session_id'])
        signals=[a for a in actions if a['kind']=='signal' and str(a.get('session_id'))==sid]
        errors=[]
        if [(a['role'],a['signal']) for a in signals]!=expected:errors.append('signal sequence differs')
        if any(a.get('syscall_result')!=0 or a.get('pid',0)<=0 or a.get('start_ticks',-1)<0 for a in signals):errors.append('OS signal failed')
        for signal in signals:
            if signal['role']=='worker' and (signal['pid']!=record.get('worker_pid') or str(signal['start_ticks'])!=str(record.get('worker_start_ticks'))):
                errors.append('worker lifetime mismatch')
        requests=[a for a in actions if a['kind']=='request']
        statuses=[a for a in requests if a['request'].get('op')=='status' and a['request'].get('session')==sid and a['response'].get('ok')]
        if not signals or not any(a['response']['data'].get('window') for a in statuses if a['after_ns']<=signals[0]['before_ns']):
            errors.append('no pre-signal armed window observation')
        if nonce=='workerCrash':
            if record.get('result')!='FAILED' or record.get('objects_absent') is not True or record.get('finalized') is not True:
                errors.append('crashed worker not finalized cleanly')
        elif nonce=='controllerStop':
            if len(signals)!=2 or signals[0]['pid']!=signals[1]['pid'] or signals[0]['start_ticks']!=signals[1]['start_ticks'] or signals[1]['before_ns']-signals[0]['after_ns']<2_500_000_000:
                errors.append('controller pause lifetime/duration differs')
            if record.get('result')!='COMPLETE' or record.get('objects_absent') is not True:
                errors.append('worker did not finish after controller pause')
        else:
            recovery=[a for a in requests if a['request'].get('op')=='recover' and a['response'].get('ok') and str(a['response'].get('data',{}).get('session_id'))==sid]
            if len(recovery)!=1 or record.get('state')!='IDLE' or record.get('recovery')!='administrator_checked_pid_absent_and_inventory_absent':
                errors.append('durable recovery missing')
            elif not any(a['response'].get('ok') and a['response'].get('data',{}).get('state')=='FAULTED' and signals[-1]['after_ns']<a['before_ns']<recovery[0]['before_ns'] for a in requests if a['request'].get('op')=='status'):
                errors.append('FAULTED barrier not observed before recovery')
        results[nonce]=dict(status='FAIL' if errors or not clean_exit else 'PASS',errors=errors,session_id=sid)
    return dict(status='FAIL' if any(x['status']=='FAIL' for x in results.values()) else 'BLOCKED' if any(x['status']=='BLOCKED' for x in results.values()) else 'PASS',
                cases=results,full_lifecycle_complete=False,
                scope='five explicit crash/stop cases; does not prove all IO publication and concurrent restart boundaries')
