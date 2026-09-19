# SPDX-License-Identifier: GPL-2.0
"""Native synchronous writeback contexts, not exclusive inode/writer ownership."""
from collections import Counter, defaultdict
import json

from explain import within_window
from owner_report import fields

FIELDS = set('protocol sample_time_ns episode_ns phase inode ino inode_generation dev_major dev_minor '
             'folio_index tid task_start actor_id actor_generation wbc memcg wb_owner_id '
             'wb_owner_generation request request_episode'.split())
FIXED = ('id','generation','inode','ino','inode_generation','dev_major','dev_minor','tid','task_start',
         'actor_id','actor_generation','wbc','memcg','wb_owner_id','wb_owner_generation')


def analyze_writeback(record, raw, requests):
    groups=defaultdict(list); dirty=[]; defects=Counter(); unknown=Counter(); count=0
    identities=dict(record.get('root_identities',{})); identities.update(record.get('owner_identities',{}))
    known={(v['id'],v['generation']) for v in identities.values()}
    for line in raw.splitlines():
        row=json.loads(line)
        if row.get('kind')!='WRITEBACK': continue
        count+=1
        if count>16384: defects['writeback_report_capacity']+=1; continue
        d=fields(row.get('detail','')); d.update(id=row.get('id'),generation=row.get('generation'))
        if (not FIELDS<=d.keys() or any(type(d[k]) is not int or d[k]<0 for k in FIELDS) or
                d['protocol']!=1 or d['phase'] not in (1,2,3,4) or
                not all(d[k] for k in ('inode','ino','tid','episode_ns'))):
            defects['writeback_schema']+=1; continue
        selected=(d['id'],d['generation']); actor=(d['actor_id'],d['actor_generation'])
        owner=(d['wb_owner_id'],d['wb_owner_generation'])
        if (selected not in known or actor!=(0,0) and actor not in known or
                owner!=(0,0) and owner not in known or selected not in (actor,owner) or
                not d['task_start'] and actor!=(0,0)):
            defects['writeback_identity']+=1; continue
        if not within_window(record,d['episode_ns'],d['sample_time_ns']):
            defects['writeback_outside_window']+=1; continue
        if d['phase']==1:
            if (actor!=selected or d['episode_ns']!=d['sample_time_ns'] or
                    any(d[k] for k in ('wbc','memcg','wb_owner_id','wb_owner_generation','request','request_episode'))):
                defects['writeback_dirty_schema']+=1; continue
            dirty.append(dict(inode=d['inode'],ino=d['ino'],inode_generation=d['inode_generation'],
                device=[d['dev_major'],d['dev_minor']],folio_index=d['folio_index'],time_ns=d['sample_time_ns'],
                actor=[*actor,d['tid'],d['task_start']],evidence='E1',
                lifetime='single_observation_only',all_writes_covered=False))
            continue
        if (not d['wbc'] or d['folio_index'] or
                d['phase']==4 and (not d['request'] or d['request_episode']!=d['sample_time_ns']) or
                d['phase']!=4 and (d['request'] or d['request_episode'])):
            defects['writeback_context_schema']+=1; continue
        key=(d['tid'],d['task_start'],d['episode_ns'])
        if key not in groups and len(groups)>=4096: defects['writeback_episode_capacity']+=1; continue
        groups[key].append(d)
    available='wb_begin' in record.get('inventory',{}).get('program_names',[])
    if count and not available: defects['writeback_missing_producer']+=1
    lookup={(r['request'],r['episode_ns']):r for r in requests}
    contexts=[]; links=[]; times=defaultdict(list); linked=set()
    for key,rows in sorted(groups.items()):
        rows.sort(key=lambda d:d['sample_time_ns']); begin=rows[0]
        if begin['phase']!=2 or begin['sample_time_ns']!=begin['episode_ns']:
            unknown['writeback_start_unobserved']+=1; continue
        if any(tuple(r[k] for k in FIXED)!=tuple(begin[k] for k in FIXED) for r in rows):
            defects['writeback_context_changed']+=1; continue
        if sum(r['phase']==2 for r in rows)!=1 or sum(r['phase']==3 for r in rows)>1:
            defects['writeback_duplicate_boundary']+=1; continue
        if rows[-1]['phase']!=3:
            unknown['writeback_end_unobserved']+=1; continue
        end=rows[-1]['sample_time_ns']
        if any(r['phase']!=4 for r in rows[1:-1]): defects['writeback_boundary_order']+=1; continue
        context=dict(episode_ns=key[2],interval_ns=[key[2],end],inode=begin['inode'],ino=begin['ino'],
            inode_generation=begin['inode_generation'],device=[begin['dev_major'],begin['dev_minor']],
            executor=[begin['actor_id'],begin['actor_generation'],*key[:2]],wbc=begin['wbc'],
            memcg=begin['memcg'],wb_owner=[begin['wb_owner_id'],begin['wb_owner_generation']],
            evidence='E2',lifetime='synchronous_I_SYNC_call_only',exclusive_dirtier=None,blocking_container=None)
        times[key[:2]].append([key[2],end]); contexts.append(context)
        for event in rows[1:-1]:
            rqkey=(event['request'],event['request_episode']); request=lookup.get(rqkey)
            if not request: unknown['writeback_request_unobserved']+=1; continue
            if (rqkey in linked or request['submitter']!=context['executor'] or
                    not key[2]<=rqkey[1]<=end):
                defects['writeback_request_context_conflict']+=1; continue
            linked.add(rqkey)
            links.append(dict(request=list(rqkey),context=context,
                relation='request_submitted_during_inode_writeback',not_exclusive_bio_content=True))
    for intervals in times.values():
        intervals.sort()
        if any(a[1]>=b[0] for a,b in zip(intervals,intervals[1:])):
            defects['writeback_overlapping_task_contexts']+=1
    if defects: contexts=[]; links=[]; dirty=[]
    return dict(coverage='AVAILABLE' if available else 'HISTORICAL_NOT_RECORDED',contexts=contexts,
        request_links=links,dirty_observations=dirty,uncertainty=dict(unknown),
        limits=['dirty folio transitions do not enumerate every write or the unique writer',
                'inode address, number and generation are observations, not a lifetime bridge to earlier dirtying',
                'memcg writeback attribution is distinct from bio blkcg billing',
                'request context does not prove all merged bio contents belong to that inode',
                'asynchronous submissions outside a closed observed call remain unknown']),dict(defects)
