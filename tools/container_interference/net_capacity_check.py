# SPDX-License-Identifier: GPL-2.0
"""A full Socket watch map must reject attribution, not truncate it silently."""
import json
from owner_report import fields
from unified_report import analyze


def check(window,logs,record=None,raw=None,idle=None):
    errors=[]; cookies=[]; after=[]
    if len(logs)!=2: raise ValueError('two capacity actors required')
    for actor,log in enumerate(logs):
        rows=[fields(line) for line in log.splitlines() if line.startswith('CIS_NET_CAPACITY ')]
        post=[fields(line) for line in log.splitlines() if line.startswith('CIS_NET_CAPACITY_AFTER ')]
        if [r.get('index') for r in rows]!=list(range(40)) or len(post)!=1:
            errors.append('capacity_population'); continue
        for row in rows:
            if (row['actor']!=actor or not row['cookie'] or not
                window['start_ns']<=row['begin_ns']<row['end_ns']<=window['end_ns']):
                errors.append('capacity_truth')
            cookies.append(row['cookie'])
        if (post[0]['actor']!=actor or post[0]['operations']!=40 or post[0]['errors'] or
                idle is None or not idle['after_ns']<post[0]['begin_ns']<post[0]['end_ns']):
            errors.append('post_detach_business')
        after.append(post[0])
    if len(cookies)!=80 or len(set(cookies))!=80: errors.append('native_cookie_population')
    quality=None; terminal=None
    if record is not None:
        report=analyze(record,raw); quality=report['quality']; terminal=quality['terminal']
        if (record['collector']!='net' or record.get('objects_absent') is not True or
                record.get('finalized') is not True or record.get('state')!='IDLE' or
                not terminal.get('valid') or terminal.get('rejected',0)<=0):
            errors.append('capacity_audit_or_cleanup')
        if quality['status']!='FAIL' or 'terminal.rejected' not in quality['defects'] or report['relations']:
            errors.append('incomplete_capacity_admitted')
        if quality.get('budget_abort'): errors.append('unrelated_budget_abort')
        observed={fields(row['detail']).get('cookie') for row in map(json.loads,raw.splitlines()) if row.get('kind')=='NET'}
        if report['specialist']['sockets'] or len(observed)!=64 or not observed<=set(cookies):
            errors.append('expected_native_watch_capacity')
    return dict(status='FAIL' if errors else 'PASS',errors=sorted(set(errors)),native_cookies=len(cookies),
        watch_capacity=64,post_detach=after,quality=quality,terminal=terminal,
        scope='watch-capacity rejection and business continuation, not dense-network profiling acceptance')
