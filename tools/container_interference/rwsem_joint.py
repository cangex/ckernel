# SPDX-License-Identifier: GPL-2.0
"""Frozen ordinary-container population around independently bracketed rwsems."""
from joint_costs import analyze as cost_analysis, rwsem_audit_delta
from joint_vm_check import workload

PLAN = dict(schema='cis-rwsem-joint-v2', registered_roots=4,
            targets_by_round=[[0,1],[2,3],[0,3]],
            ordinary_cpus=[0,0,1,1], ordinary_workloads=['file','file','vma','vma'],
            offered_per_actor=1500, period_ns=2_000_000, timeout_ns=100_000_000,
            baseline='same-kernel idle controller, same fixture case without probes',
            p99='record_only', memory='bookends, not exclusive observer allocation',
            scope='four active ordinary containers plus controlled native rwsem operations')


def roles(round_number):
    targets = PLAN['targets_by_round'][round_number]
    return targets + [i for i in range(4) if i not in targets]


def verify_fixture_schedule(state):
    mapping = roles(state['round'])
    case = state['case']
    expected = []
    def add(actor, generation=0, **args):
        normalized = dict(reset=False,slot=0,mode=0,hold=0,wait_slot=0,wait_holders=0)
        normalized.update(args)
        expected.append((mapping[actor],generation,normalized))
    def reset(generation=0):
        for slot in (0,1): add(0,generation,reset=True,slot=slot)
    reset()
    if case=='readers':
        add(0,mode=0,hold=200); add(2,mode=0,hold=200); add(1,mode=1,wait_holders=2)
    elif case=='reuse':
        add(0,mode=1,hold=200); add(1,mode=0,wait_holders=1)
        reset(1); add(0,1,mode=1,hold=200); add(1,1,mode=0,wait_holders=1)
    elif case in ('writeRead','writeWrite','private','tryFailure','abort','nonOwner','preWindow','downgrade'):
        add(0,mode=4 if case=='nonOwner' else 5 if case=='downgrade' else 1,
            hold=500 if case=='preWindow' else 200)
        add(1,slot=1 if case=='private' else 0,
            mode=1 if case in ('writeWrite','nonOwner','downgrade') else 2 if case=='tryFailure' else 6 if case=='abort' else 0,
            wait_holders=1)
    else:
        raise ValueError('unknown joint fixture case')
    jobs=state['jobs']
    if len(jobs)!=len(expected) or state['logs']!=[j['log'] for j in jobs] or len(set(state['logs']))!=len(jobs):
        raise ValueError('joint fixture job population')
    token=jobs[0]['token']
    for job,(actor,generation,args) in zip(jobs,expected):
        actual=dict(reset=False,slot=0,mode=0,hold=0,wait_slot=0,wait_holders=0)
        actual.update(job['arguments'])
        if job['actor_index']!=actor or job['token']!=token+generation or actual!=args:
            raise ValueError('joint fixture schedule or role changed')


def verify(plan, state, logs, record, hz):
    if plan != PLAN:
        raise ValueError('rwsem joint plan changed')
    verify_fixture_schedule(state)
    info = state['joint']
    if len(info['logs']) != 4 or len(set(info['logs'])) != 4 or info['exit_codes'] != [0]*4:
        raise ValueError('four complete joint workloads required')
    if state['targets'] != [state['registered'][i] for i in roles(state['round'])[:2]]:
        raise ValueError('joint target rotation')
    work = [workload(logs[name]) for name in info['logs']]
    for actor, row in enumerate(work):
        if (row['mode'] != PLAN['ordinary_workloads'][actor] or
                row['due_start_ns'] != info['start_ns'] or row['timeouts']):
            raise ValueError('joint business correctness/binding')
    if record and not info['start_ns'] < record['window']['start_ns'] < record['window']['end_ns'] < min(w['end_ns'] for w in work):
        raise ValueError('ordinary business does not cover full diagnostic window')
    if not info['before']['read_end_ns'] < info['start_ns'] < max(w['end_ns'] for w in work) < info['after']['time_ns']:
        raise ValueError('joint accounting boundary')
    resources = cost_analysis(info['before'], info['after'], hz)
    source = rwsem_audit_delta(info['before']['rwsem_source_audit'],
                              info['after']['rwsem_source_audit'])
    if min(source['selected'], *(r['selected'] for r in source['per_cpu'])) < 0:
        raise ValueError('inconsistent rwsem source audit bookends')
    if state['enabled'] and (not source['selected'] or not source['filtered']):
        raise ValueError('native rwsem filter not exercised')
    if not state['enabled'] and source['entries']:
        raise ValueError('rwsem source active in OFF case')
    if record:
        receipt=record['receipt']; terminal=receipt['terminal']
        if (terminal.get('valid') is not True or type(terminal.get('received')) is not int or
                not 0<=terminal['received']<=source['selected']):
            raise ValueError('rwsem BPF entries exceed audited selected source')
        if not info['before']['read_end_ns'] < record['requested_ns'] <= receipt['prepared_ns'] < receipt['destroyed_ns'] < info['after']['time_ns']:
            raise ValueError('rwsem source bookends do not contain producer lifetime')
    return dict(workload=work, system_cost=resources,
                native_source=source,
                scope='fixture and ordinary operations plus controller; not exclusive observer CPU',
                observer_kernel_cpu_complete=False, observer_memory_complete=False)


def comparisons(states):
    result = []
    for state in states:
        if not state['enabled']:
            continue
        before = [s for s in states if not s['enabled'] and (s['round'],s['case']) == (state['round'],state['case'])]
        if len(before) != 1:
            raise ValueError('one same-case OFF state required')
        for actor, (a,b) in enumerate(zip(before[0]['joint']['workload'],state['joint']['workload'])):
            result.append(dict(round=state['round'], case=state['case'], actor=actor,
                role='target' if actor in roles(state['round'])[:2] else 'bystander',
                throughput_change_fraction=b['throughput_per_second']/a['throughput_per_second']-1,
                p99_change_ns=b['p99_ns']-a['p99_ns'],
                p99_change_fraction=None if not a['p99_ns'] else b['p99_ns']/a['p99_ns']-1,
                timeouts_before=a['timeouts'], timeouts_after=b['timeouts']))
    return result
