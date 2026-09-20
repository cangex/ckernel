# SPDX-License-Identifier: GPL-2.0
"""Independent-file I/O truth, without an exclusive blocker assertion."""
from owner_report import fields

CASES={'shared_sync':dict(disks=[0,0],mode='sync'),
       'separate_sync':dict(disks=[0,1],mode='sync'),
       'shared_buffered':dict(disks=[0,0],mode='buffered'),
       'separate_buffered':dict(disks=[0,1],mode='buffered')}


def case_order():
    return [dict(case=c,round=r,enabled=v,label=c+str(r)+('on' if v else 'off'))
            for r in range(3) for c in CASES for v in ((False,True) if r%2==0 else (True,False))]


def check_case(case,window,logs,report=None,identities=None):
    errors=[]; actors=[]
    for role,log in enumerate(logs):
        rows=[fields(line) for line in log.splitlines() if line.startswith('CIS_IO_DONE ')]
        if len(rows)!=1: errors.append('workload_receipt'); continue
        d=rows[0]; actors.append(d)
        if (d.get('role')!=role or d.get('bytes')!=8388608 or d.get('verified')!=1 or d.get('errors')!=0 or
                d.get('sync_each')!=int(CASES[case]['mode']=='sync') or
                not window['start_ns']<=d.get('begin_ns',0)<window['end_ns'] or
                not d['begin_ns']<d.get('written_ns',0)<=d.get('synced_ns',0)<=d.get('end_ns',0) or
                d['end_ns']-d['begin_ns']>20_000_000_000): errors.append('workload_window_or_correctness')
    if len(actors)==2:
        a,b=actors; same=(a['major'],a['minor'])==(b['major'],b['minor'])
        if same!=case.startswith('shared'): errors.append('device_layout')
        if same and (a['directory_inode']==b['directory_inode'] or a['inode']==b['inode']):
            errors.append('objects_not_private')
    if report is not None:
        if report['quality']['status']!='PASS' or report['scope_audit']['status']!='PASS': errors.append('collector_quality')
        pressure=report['pressure']; shots=pressure['tag_snapshots']; pauses=pressure['dirty_pauses']
        expected={tuple(i[k] for k in ('id','generation')) for i in identities}
        if {tuple(s['selected_container']) for s in shots}!=expected: errors.append('missing_issue_tag_actor')
        if case.endswith('buffered') and not any(p['positive_pause_requested'] for p in pauses):
            errors.append('missing_native_dirty_pause')
        if any(p['blocking_container'] is not None for p in pauses+shots): errors.append('invented_blocker')
        if pressure['total_pool_occupancy']!='UNKNOWN': errors.append('invented_population')
        if len(actors)==2:
            for identity,actor in zip(identities,actors):
                who=[identity['id'],identity['generation']]
                if any(s['device']!=[actor['major'],actor['minor']] for s in shots if s['selected_container']==who):
                    errors.append('device_misattribution')
        if case.startswith('separate'):
            pools=[{s['pool'] for s in shots if s['selected_container']==[i['id'],i['generation']]} for i in identities]
            if pools[0]&pools[1]: errors.append('false_shared_pool')
    return dict(status='FAIL' if errors else 'PASS',errors=errors,actors=actors)
