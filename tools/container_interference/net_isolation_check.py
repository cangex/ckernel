# SPDX-License-Identifier: GPL-2.0
"""Independent native namespace FDs and cgroup CPU counters, not probe truth."""
from owner_report import fields

QUOTA_CONFIG=['20000 100000','max 100000']


def namespaces(case,logs,report=None):
    errors=[]; rows=[]
    for actor,log in enumerate(logs):
        facts=[fields(line) for line in log.splitlines() if line.startswith('CIS_NET_NAMESPACE ')]
        used={fields(line).get('cookie') for line in log.splitlines() if line.startswith('CIS_NET_TRUTH ')}
        if (len(facts)!=1 or facts[0].get('actor')!=actor or
                any(type(facts[0].get(k)) is not int or facts[0][k]<=0 for k in ('cookie','task_ns','socket_ns')) or
                used!={facts[0].get('cookie')}):
            errors.append('namespace_truth_'+str(actor)); continue
        fact=facts[0]; rows.append(fact)
        if report is not None:
            sockets=[s for s in report['sockets'] if s['cookie']==fact['cookie']]
            if len(sockets)!=1 or sockets[0]['netns']!=fact['socket_ns']:
                errors.append('socket_namespace_not_observed_'+str(actor))
            elif not any(a[2]&0xffffffff==fields(line)['host_pid'] for a in sockets[0]['observed_actors']
                         for line in log.splitlines() if line.startswith('CIS_SESSION_CONTAINER ')):
                errors.append('private_actor_not_observed_'+str(actor))
    if len(rows)==2:
        a,b=rows
        if a['task_ns']==b['task_ns']: errors.append('tasks_not_network_isolated')
        if case=='rightsPrivate':
            if any(r['task_ns']!=r['socket_ns'] for r in rows): errors.append('private_socket_namespace')
        elif case in ('rightsShared','rightsAccept'):
            if a['socket_ns']!=a['task_ns'] or b['socket_ns']!=a['socket_ns'] or b['socket_ns']==b['task_ns']:
                errors.append('transferred_socket_namespace')
        elif case=='private':
            if a['socket_ns']!=b['socket_ns'] or any(r['task_ns']==r['socket_ns'] for r in rows):
                errors.append('inherited_socket_namespace')
        else: errors.append('unsupported_namespace_case')
    return dict(status='FAIL' if errors else 'PASS',errors=errors,truth=rows)


def quota(window,logs,before,after):
    errors=[]; deltas=[]; work=[]
    for actor,log in enumerate(logs):
        rows=[fields(line) for line in log.splitlines() if line.startswith('CIS_NET_QUOTA ')]
        if len(rows)!=(0 if actor else 1): errors.append('quota_work_shape'); continue
        if rows:
            r=rows[0]; work.append(r)
            if (r.get('actor')!=0 or r.get('requested_cpu_ns')!=80000000 or
                    not window['start_ns']<=r.get('begin_ns',-1)<=r.get('end_ns',-1)<=window['end_ns'] or
                    not 80000000<=r.get('cpu_end_ns',0)-r.get('cpu_begin_ns',0)<=85000000 or
                    r['end_ns']-r['begin_ns']<=r['cpu_end_ns']-r['cpu_begin_ns']):
                errors.append('quota_work_values')
        first,last=before['roots'][actor],after['roots'][actor]
        if any(x.get('cpu.max','').strip()!=QUOTA_CONFIG[actor] for x in (first,last)):
            errors.append('quota_configuration')
        def counters(snapshot):
            pairs=[line.split() for line in snapshot['cpu.stat'].splitlines()]
            if any(len(p)!=2 for p in pairs) or len({p[0] for p in pairs})!=len(pairs):
                raise ValueError('cpu.stat fields')
            return {k:int(v) for k,v in pairs}
        start,end=counters(first),counters(last)
        d={k:end[k]-start[k] for k in ('nr_throttled','throttled_usec','usage_usec')}
        deltas.append(d)
        if any(v<0 for v in d.values()): errors.append('quota_counter_regressed')
        if actor==0 and (d['nr_throttled']<1 or d['throttled_usec']<=0 or d['usage_usec']<80000):
            errors.append('quota_not_exercised')
        if actor==1 and (d['nr_throttled'] or d['throttled_usec']): errors.append('bystander_throttled')
    return dict(status='FAIL' if errors else 'PASS',errors=errors,work=work,cpu_deltas=deltas,
                scope='CPU quota before private Socket lock; not cross-container lock interference')
