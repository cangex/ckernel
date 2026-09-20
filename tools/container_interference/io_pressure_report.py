# SPDX-License-Identifier: GPL-2.0
"""Bounded public I/O associations, never inferred exclusive blocking owners."""
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
import json
from explain import within_window
from owner_report import fields


def analyze_pressure(record,raw,requests,groups,tags):
    defects=Counter(); snapshots=[]; pauses=[]; seen=set(); joined=[]
    identities=dict(record.get('root_identities',{})); identities.update(record.get('owner_identities',{}))
    known={(x['id'],x['generation']) for x in identities.values()}
    lookup={(r['request'],r['episode_ns']):r for r in requests}
    pool_index=defaultdict(list); pool_times={}; count=0
    for line in raw.splitlines():
        row=json.loads(line); kind=row.get('kind')
        if kind not in ('BLOCK_POOL','DIRTY_PAUSE'): continue
        count+=1
        if count>8192: defects['pressure_record_capacity']+=1; continue
        d=fields(row.get('detail','')); who=(row.get('id'),row.get('generation'))
        if who not in known: defects['pressure_identity']+=1; continue
        if kind=='BLOCK_POOL':
            required=set('protocol sample_time_ns request episode_ns queue pool kind tag depth reserved_tags pool_depth dev_major dev_minor'.split())
            if (not required<=d.keys() or any(type(d[k]) is not int or d[k]<0 for k in required) or
                    d['protocol']!=1 or d['kind'] not in (1,2) or
                    not all(d[k] for k in ('request','episode_ns','queue','pool','depth')) or
                    d['tag']>=d['depth'] or d['reserved_tags']>d['depth'] or
                    d['pool_depth']>d['depth'] or not within_window(record,d['episode_ns'],d['sample_time_ns'])):
                defects['pool_snapshot_schema']+=1; continue
            key=(d['request'],d['episode_ns']); request=lookup.get(key)
            issue=[r for r in groups.get(key,[]) if r['phase']==3 and r['sample_time_ns']==d['sample_time_ns']]
            if (not request or len(issue)!=1 or list(who)!=request['selected_container'] or
                    issue[0]['queue']!=d['queue'] or
                    (issue[0]['dev_major'],issue[0]['dev_minor'])!=(d['dev_major'],d['dev_minor'])):
                defects['pool_snapshot_request_binding']+=1; continue
            identity=(*key,d['sample_time_ns'],d['kind'])
            if identity in seen: defects['pool_duplicate_snapshot']+=1; continue
            seen.add(identity)
            reserved=d['tag']<d['reserved_tags']; bit=d['tag'] if reserved else d['tag']-d['reserved_tags']
            item=dict(request=list(key),time_ns=d['sample_time_ns'],queue=d['queue'],pool=d['pool'],
                device=[d['dev_major'],d['dev_minor']],kind='driver' if d['kind']==1 else 'scheduler',
                tag=d['tag'],reserved=reserved,pool_depth=d['pool_depth'],within_current_depth=bit<d['pool_depth'],
                selected_container=list(who),submitter=request['submitter'],
                evidence='E1',relation='tag_assigned_at_observed_issue',holder=None,blocking_container=None,
                lifetime='point_observation_only',all_slots_observed=False)
            snapshots.append(item)
            if item['within_current_depth']:
                pool_index[(d['queue'],d['pool'],d['dev_major'],d['dev_minor'])].append(item)
        else:
            required=set('protocol begin_ns end_ns tid task_start cgroup_id wb bdi bdi_id wb_memcg wb_owner_id wb_owner_generation dirty threshold wb_dirty wb_threshold requested_jiffies remaining_jiffies cpu stack_id'.split())
            if (not required<=d.keys() or any(type(d[k]) is not int for k in required) or
                    any(d[k]<0 for k in required-{'stack_id','requested_jiffies','remaining_jiffies'}) or
                    d['protocol']!=1 or not all(d[k] for k in ('begin_ns','tid','task_start','cgroup_id','wb','bdi')) or
                    d['end_ns']<d['begin_ns'] or not within_window(record,d['begin_ns'],d['end_ns']) or
                    d['cpu']>=512 or d['stack_id'] < -4095):
                defects['dirty_pause_schema']+=1; continue
            owner=(d['wb_owner_id'],d['wb_owner_generation'])
            if owner!=(0,0) and owner not in known: defects['dirty_pause_owner_identity']+=1; continue
            identity=(kind,d['tid'],d['task_start'],d['begin_ns'])
            if identity in seen: defects['dirty_pause_duplicate']+=1; continue
            seen.add(identity)
            pauses.append(dict(actor=[*who,d['tid'],d['task_start']],interval_ns=[d['begin_ns'],d['end_ns']],
                resource=dict(kind='backing_device',address=d['bdi'],id=d['bdi_id']),wb=d['wb'],
                wb_memcg=d['wb_memcg'],wb_owner=list(owner) if all(owner) else None,
                dirty_pages=d['dirty'],threshold_pages=d['threshold'],wb_dirty_pages=d['wb_dirty'],
                wb_threshold_pages=d['wb_threshold'],requested_jiffies=d['requested_jiffies'],
                remaining_jiffies=d['remaining_jiffies'],positive_pause_requested=d['requested_jiffies']>0,
                stack_id=d['stack_id'],evidence='E1',blocking_container=None,exclusive_dirtier=None,
                wall_bracket_is_pure_sleep=False))
    for key,items in pool_index.items():
        items.sort(key=lambda x:x['time_ns']); pool_times[key]=[x['time_ns'] for x in items]
    for wait in tags:
        for span in wait['sleep_intervals']:
            key=(wait['queue'],span['pool'],*wait['device']); times=pool_times.get(key,[])
            lo=bisect_left(times,span['interval_ns'][0]); hi=bisect_right(times,span['interval_ns'][1])
            if hi-lo>64 or len(joined)+hi-lo>4096:
                defects['pool_overlap_capacity']+=1; continue
            for shot in pool_index.get(key,[])[lo:hi]:
                joined.append(dict(waiter=wait['container'],wait_episode_ns=wait['episode_ns'],
                    waiter_task=[wait['tid'],wait['task_start']],
                    wait_interval_ns=span['interval_ns'],snapshot=shot,evidence='E2',
                    relation='tag_observed_in_waited_pool_during_wait',blocking_container=None,
                    exclusive_request_owner=None,causal='NOT_ESTABLISHED'))
    if defects: snapshots=[]; joined=[]; pauses=[]
    return dict(schema='cis-io-pressure-v1',tag_snapshots=snapshots,wait_pool_associations=joined,
        dirty_pauses=pauses,total_pool_occupancy='UNKNOWN',all_blockers='UNKNOWN',
        limits=['tag snapshots are points, not allocation-to-release slot ownership or occupancy percentages',
                'same pool during a wait is a direct association, not proof that the observed request caused the wait',
                'initial submitter, merged-bio billing and writeback accounting remain distinct',
                'pause wall time includes scheduling and observer effects; requested jiffies are not measured sleep',
                'dirty/threshold values are the native decision context, not a synchronized global snapshot',
                'device-internal causes and unobserved requests remain unknown']),dict(defects)
