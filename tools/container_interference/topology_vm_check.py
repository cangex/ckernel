# SPDX-License-Identifier: GPL-2.0
"""Recompute live topology negatives from saved snapshots, not PASS text."""
import argparse
import hashlib
import json
from pathlib import Path

import resource_topology as t
from session_check import extract
from source_switches import validate


def check(serial):
    raw=serial.read_bytes()
    if len(raw)>128<<20:raise ValueError('serial capacity')
    text=raw.decode();files=extract(text);prefix='/tmp/topology-evidence/'
    def value(name):return json.JSONDecoder().raw_decode(files[prefix+name].lstrip())[0]
    rows=value('snapshots.json');declared=value('result.json')
    checks={}
    for name,row in rows.items():
        if name!='deleted':
            checks['identity_'+name]=row['identity_valid'] and row['status']=='OBSERVED_ENDPOINT'
        checks['bounded_'+name]=(row['read_cost']['reads']<=t.LIMITS['reads'] and
                                 row['read_cost']['bytes']<=t.LIMITS['bytes']+1)
        t.stable(row,row)
    for first,second in [('a0','a1'),('b0','b1')]:
        checks[first+'_stable']=t.stable(rows[first],rows[second])['status']=='STABLE_ENDPOINTS'
    for first,second in [('a1','affinity'),('affinity','child'),('child','namespace'),
                         ('namespace','reregistered'),('reregistered','exited'),('exited','recreated')]:
        checks[first+'_invalidated']=t.stable(rows[first],rows[second])['status']=='CHANGED_INVALIDATED'
    checks['deleted']=rows['deleted']['status']=='IDENTITY_UNKNOWN'
    a,b=rows['a0'],rows['b0']
    def tmp(row):return {m['device'] for task in row['tasks'] for m in task['mounts'] if m['mountpoint']=='/tmp'}
    checks['private_tmpfs']=bool(tmp(a)) and bool(tmp(b)) and tmp(a).isdisjoint(tmp(b))
    checks['separate_networks_same_names']=(a['tasks'][0]['interfaces']==b['tasks'][0]['interfaces']==['lo'] and
                                          a['tasks'][0]['namespaces']['net']!=b['tasks'][0]['namespaces']['net'])
    expected=t.compare_roots({'a':dict(topology=a),'b':dict(topology=b)},
                            {'a':dict(topology=rows['a1']),'b':dict(topology=rows['b1'])})
    checks['shared_record']=expected==value('shared.json') and bool(expected['shared_candidates'])
    checks['no_contention_inferred']=all(r['evidence']=='CONFIGURATION_ONLY' and r['contention']=='NOT_INFERRED'
                                         for r in expected['shared_candidates'])
    checks['declared_checks']=declared['status']=='PASS' and all(declared['checks'].values())
    checks['guest_exit']='CIS_PROFILE_VM_EXIT=0' in text.splitlines()
    checks['no_kernel_warning']=not any(v in text for v in ('Oops:','Kernel panic','BUG: KASAN:','WARNING: CPU:'))
    for name in ('before_sources','after_sources'):validate(declared[name],None,0,2**64-1)
    return dict(schema='cis-y1-topology-check-v1',status='PASS' if all(checks.values()) else 'FAIL',checks=checks,
                serial_sha256=hashlib.sha256(raw).hexdigest(),scope='configured_resources_and_invalidation_only',
                snapshot_costs={k:v['read_cost'] for k,v in rows.items()},y7_complete=False)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('serial',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
    result=check(a.serial)
    with a.output.open('x') as f:json.dump(result,f,indent=2)
    print(json.dumps(dict(status=result['status'],checks=result['checks'])))
    raise SystemExit(result['status']!='PASS')
