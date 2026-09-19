# SPDX-License-Identifier: GPL-2.0
"""Independent private-tree/copy/reinitialization truth, not fixture event counts."""
from owner_report import fields


def check_work(window, logs, report=None, identities=None):
    errors, participants, private_trees = [], [], []
    if len(logs)!=2: raise ValueError('two independent file contexts required')
    for i, log in enumerate(logs):
        pids=[fields(l).get('host_pid',0) for l in log.splitlines() if l.startswith('CIS_SESSION_CONTAINER ')]
        truth=[fields(l) for l in log.splitlines() if l.startswith('CIS_MAPLE_TRUTH ')]
        expected=[(c,a) for c in range(2) for a in range(1,5)]
        if (len(pids)!=1 or not pids[0] or [(v['cycle'],v['action']) for v in truth]!=expected or
                any(not window['start_ns']<=v['begin_ns']<v['end_ns']<=window['end_ns'] or
                    v['generation']!=v['cycle']+1 or not v['tree0'] or not v['tree1'] or v['tree0']==v['tree1'] or
                    v['cpu']!=i+(2 if v['action']==3 else 0) or
                    v['verified']!=(32*v['action'] if v['action']<=2 else 0) for v in truth) or
                len({(v['tree0'],v['tree1']) for v in truth})!=1):
            errors.append('truth_'+str(i))
        private_trees.append({v[k] for v in truth for k in ('tree0','tree1')})
        joins=[]
        if report is not None:
            actor=[identities[i]['id'],identities[i]['generation']]
            for v in truth:
                calls=[c for c in report['calls'] if c['actor'][:2]==actor and
                       c['actor'][2]&0xffffffff==pids[0] and
                       v['begin_ns']<=c['interval_ns'][0]<=c['interval_ns'][1]<=v['end_ns']]
                if v['action']<=2:
                    if not calls: errors.append('no_observed_backend_'+str(i))
                    for c in calls:
                        context=c.get('maple_context')
                        if (not context or context['tree_address']!=v['tree0' if v['action']==1 else 'tree1'] or
                                not v['begin_ns']<=context['allocation_bracket_ns'][0]<context['allocation_bracket_ns'][1]<=v['end_ns'] or
                                c['sample_shift']!=0): errors.append('wrong_destination_'+str(i))
                        else: joins.append(dict(cycle=v['cycle'],action=v['action'],backend_call_ns=c['call_ns'],
                                                tree=context['tree_address'],cpu=c['object_samples'][0]['cpu'] if c['object_samples'] else None))
                elif any(c.get('maple_context') for c in calls): errors.append('unexpected_allocation_on_destroy_'+str(i))
            releases=[f for f in report['lifetimes']['release_entries'] if f['allocation_requester'][:2]==actor and
                      f.get('allocation_tree_context') and f['allocation_tree_context']['tree_address'] in private_trees[-1]]
            if not releases: errors.append('no_allocation_to_release_'+str(i))
            participants.append(dict(actor=actor,truth=truth,joins=joins,release_entries=len(releases),
                release_contexts=sorted({v['release_executor']['context'] for v in releases})))
    if private_trees[0]&private_trees[1]: errors.append('private_fixture_objects_shared')
    if report is not None:
        for key in ('quality','scope_audit','maple','lifetimes'):
            if report[key]['status']!='PASS': errors.append(key)
    return dict(status='FAIL' if errors else 'PASS',errors=errors,participants=participants,
                scope='private destinations, copy destination, same-address reinitialization and release provenance',
                recall=None,performance_certification='NOT_ACCEPTED')
