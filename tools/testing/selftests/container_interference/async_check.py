#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Fixture-only submit/execute/cancel truth, never generic worker ownership."""
import argparse
import json
import pathlib
import re
FIELDS=re.compile(r'(\w+)=([^ ;]+)')


def analyze(text):
    truths, observations, failures=[], [], []
    for line in text.splitlines():
        if line.startswith('CIS_ASYNC '):
            truths.append(dict(FIELDS.findall(line)))
        elif line.startswith('{'):
            try:
                record=json.loads(line)
            except ValueError:
                continue
            if record.get('kind')=='async_submitter':
                f=dict(FIELDS.findall(record['detail']))
                f['id']=record['id']
                observations.append(f)
    confirmed=[]
    for t in truths:
        later=[int(other['queued_ns']) for other in truths
               if other['object']==t['object'] and other['owner']==t['owner'] and
               int(other['queued_ns'])>int(t['queued_ns'])]
        limit=min(later) if later else int(t['queued_ns'])+10000000
        nearby=[x for x in observations if x['object']==t['object'] and x['id']==int(t['owner']) and
                int(t['queued_ns']) <= int(x['sequence_ns']) < limit]
        sequences={int(x['sequence_ns']) for x in nearby if int(x['type'])==6}
        types={int(x['type']) for x in nearby}
        action=int(t['action'])
        if len(sequences)!=1:
            failures.append({'action':action,'reason':'queue lineage missing or ambiguous','truth':t})
        if any(int(x['sequence_ns']) not in sequences for x in nearby):
            failures.append({'action':action,'reason':'unpaired submission sequence','truth':t})
        if action==0 and not {6,7,8}.issubset(types):
            failures.append({'action':action,'reason':'ordinary execution pairing missing','truth':t})
        if action in (1,3) and 9 not in types:
            failures.append({'action':action,'reason':'cancel return missing','truth':t})
        if action==1 and any(int(x['flags']) != int(t['cancelled']) for x in nearby if int(x['type'])==9):
            failures.append({'action':action,'reason':'cancel result disagrees with truth','truth':t})
        if action==2 and 10 not in types:
            failures.append({'action':action,'reason':'self-requeue ambiguity not reported','truth':t})
        confirmed.append({'action':action,'owner':t['owner'],'worker_cgroup':t['executor'],
                          'sequence_ns':sorted(sequences),'types':sorted(types)})
    return {'truth_count':len(truths),'confirmed':confirmed,'failures':failures,
            'pass':len(truths)==8 and not failures,
            'boundary':'Only per-open cgroup-owned isolated fixture; requeued work deliberately unresolved; no general RCU/merged-work ownership.'}


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('log',type=pathlib.Path);p.add_argument('output',type=pathlib.Path)
    a=p.parse_args();r=analyze(a.log.read_text())
    with a.output.open('x') as f: json.dump(r,f,indent=2); f.write('\n')
    print(json.dumps(r,indent=2));raise SystemExit(not r['pass'])
