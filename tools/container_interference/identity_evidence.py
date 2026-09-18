# SPDX-License-Identifier: GPL-2.0
"""Re-evaluate a controlled identity migration from raw responses and IP events."""
import json
import re

from session_quality import assess


def read_one(files, suffix):
    rows=[body for name,body in files.items() if name.endswith(suffix)]
    if len(rows)!=1:raise ValueError('one raw artifact required: '+suffix)
    return rows[0]


def analyze(files, source):
    required=('/identity-result.json','/identity-requests.jsonl')
    if not all(any(n.endswith(s) for n in files) for s in required):
        return dict(status='BLOCKED',reason='raw identity request/result pair missing')
    report,_=json.JSONDecoder().raw_decode(read_one(files,required[0]).lstrip())
    sid=str(report['session_id'])
    record,_=json.JSONDecoder().raw_decode(read_one(files,'/identity-records/'+sid+'.json').lstrip())
    if str(record.get('session_id'))!=sid or {k:(record.get('source_identity') or record).get(k) for k in source}!=source:
        raise ValueError('identity session source mismatch')
    if assess(record)['status']!='PASS':
        return dict(status='FAIL',reason='migration capture incomplete',quality=assess(record))
    actions=[json.loads(x) for x in read_one(files,required[1]).splitlines() if x.startswith('{')]
    previous=-1
    for index,row in enumerate(actions,1):
        if row['sequence']!=index or row['before_ns']<previous or row['after_ns']<row['before_ns']:
            raise ValueError('unordered identity action transcript')
        previous=row['after_ns']
    def matching(op, predicate):
        return [x for x in actions if x['request'].get('op')==op and predicate(x)]
    a,b,new=report['previous_registration'],report['previous_b'],report['recreated_registration']
    if a==new or a==b or new==b or record.get('targets')!=[a,b]:
        raise ValueError('identity generations/targets mismatch')
    registered=[x['response']['data']['target'] for x in matching('register',lambda x:x['response'].get('ok') is True)]
    if registered != [a,b,new]:raise ValueError('registration transcript mismatch')
    overlap=matching('register',lambda x:x['response'].get('ok') is False and 'overlap' in str(x['response'].get('error','')))
    stale=matching('start',lambda x:x['request'].get('nonce')=='deletedRoot' and x['request'].get('targets')==[a] and x['response'].get('ok') is False and 'deleted or renamed' in str(x['response'].get('error','')))
    unregister=matching('unregister',lambda x:x['request'].get('target')==a and x['response'].get('ok') is True)
    if len(overlap)!=1 or len(stale)!=1 or len(unregister)!=1:
        raise ValueError('overlap/stale/unregister response evidence absent')
    begin,end,margin=report['moved_begin_ns'],report['moved_end_ns'],report['boundary_margin_ns']
    if begin>end or margin!=1_000_000 or not report.get('migrated_pids'):
        raise ValueError('invalid migration interval')
    counts=dict(before_a=0,after_b=0,ambiguous_boundary=0)
    wrong=[]
    for line in read_one(files,'/identity-records/'+sid+'.jsonl').splitlines():
        if not line.startswith('{'):continue
        event=json.loads(line)
        if str(event.get('session_id'))!=sid:raise ValueError('IP stream session mismatch')
        if event.get('kind')!='IP':continue
        fields=dict(re.findall(r'(\w+)=([^ ;]+)',event['detail']))
        stamp=int(fields['sample_time_ns']); actual='%s:%s'%(event['id'],event['generation'])
        if stamp<begin-margin:
            counts['before_a']+=1
            if actual!=a:wrong.append(event)
        elif stamp>end+margin:
            counts['after_b']+=1
            if actual!=b:wrong.append(event)
        else:counts['ambiguous_boundary']+=1
    if counts!=report['migration']:raise ValueError('reported counts disagree with raw IP events')
    passed=not wrong and counts['before_a']>=16 and counts['after_b']>=16
    return dict(status='PASS' if passed else 'FAIL',session_id=sid,counts=counts,wrong=wrong[:8],
                scope='controlled descendant creation, overlap rejection, one migration, stale-root rejection and generation renewal',
                remaining=['independent concurrent registration races and short-lived descendants',
                           'owner/non-target holder cases are a separate truth gate'],full_identity_complete=False)
