# SPDX-License-Identifier: GPL-2.0
"""Selected original TCP send skb headers, not packet payload ownership."""
from collections import Counter, defaultdict
import json
from explain import within_window
from owner_report import fields


def correlate(record, raw, quality, scope):
    supported='net_tx' in record.get('inventory',{}).get('program_names',[])
    required={'protocol','sample_time_ns','begin_ns','alloc_ns','backend_ns','tid','task_start','skb',
              'cookie','socket','phase','context','actor_tid','actor_start','actor_id',
              'actor_generation','cpu','netns','gfp','requested','stack_id'}
    groups=defaultdict(list); excluded=Counter(); unknown=Counter(); episodes=[]
    for line in raw.decode().splitlines():
        item=json.loads(line)
        if item.get('kind')!='NET_TX': continue
        d=fields(item.get('detail',''))
        if (not required<=d.keys() or any(type(d[k]) is not int for k in required)
                or any(d[k]<0 for k in required-{'stack_id'}) or d['protocol']!=2
                or d['phase'] not in (1,2,3,4,5) or d['context'] not in (0,1,2)
                or not all(d[k] for k in ('begin_ns','backend_ns','tid','task_start','cookie','socket','requested'))
                or not within_window(record,d['begin_ns'],d['sample_time_ns'])
                or not d['begin_ns']<=d['alloc_ns']<=d['backend_ns']<=d['sample_time_ns']):
            excluded['schema_or_window']+=1; continue
        d['requester']=[item.get('id'),item.get('generation'),d['tid'],d['task_start']]
        if not all(type(v) is int and v>0 for v in d['requester']):
            excluded['requester_identity']+=1; continue
        executor=[d[k] for k in ('actor_id','actor_generation','actor_tid','actor_start')]
        if ((d['context'] and any(executor)) or
                (d['phase']!=5 and (d['context'] or executor!=d['requester'])) or
                (d['phase']==4 and d['skb']) or (d['phase']!=4 and not d['skb'])):
            excluded['executor_or_address']+=1; continue
        key=(*d['requester'],d['begin_ns'])
        if key not in groups and len(groups)>=4096:
            excluded['capacity']+=1; continue
        groups[key].append(d)
    for key,rows in groups.items():
        rows.sort(key=lambda r:r['sample_time_ns']); begin=rows[0]
        counts=Counter(r['phase'] for r in rows)
        immutable=('cookie','socket','skb','alloc_ns','backend_ns','netns','gfp','requested')
        if (any(v>1 for v in counts.values()) or
                any(any(r[k]!=begin[k] for k in immutable) for r in rows) or
                (counts[4] and (len(rows)!=1 or begin['sample_time_ns']!=begin['backend_ns'])) or
                (not counts[4] and (counts[1]!=1 or begin['phase']!=1 or
                                   begin['sample_time_ns']!=begin['backend_ns'])) or
                counts[2]+counts[3]>1):
            excluded['ambiguous_lifetime']+=1; continue
        terminal=next((r for r in rows if r['phase'] in (2,3,4)),None)
        release=next((r for r in rows if r['phase']==5),None)
        if terminal and release and ((terminal['phase']==2 and release['sample_time_ns']<terminal['sample_time_ns'])
                                     or (terminal['phase']==3 and release['sample_time_ns']>terminal['sample_time_ns'])):
            excluded['invalid_admission_order']+=1; continue
        outcome={2:'ADMITTED',3:'MEMORY_ADMISSION_REJECTED',4:'BACKEND_ALLOCATION_FAILED'}.get(
            terminal['phase'] if terminal else 0,'UNOBSERVED')
        if not terminal: unknown['terminal_unobserved']+=1
        if not release and not counts[4]: unknown['release_unobserved']+=1
        episodes.append(dict(requester=list(key[:4]),begin_ns=key[4],cookie=begin['cookie'],
            socket_address=begin['socket'],netns=begin['netns'],skb_address=begin['skb'],
            backend_interval_ns=[begin['alloc_ns'],begin['backend_ns']],backend_wall_ns=begin['backend_ns']-begin['alloc_ns'],
            requested_header_bytes=begin['requested'],gfp=begin['gfp'],outcome=outcome,
            terminal_ns=terminal['sample_time_ns'] if terminal else None,
            release_entry_ns=release['sample_time_ns'] if release else None,
            release_executor=[release[k] for k in ('actor_id','actor_generation','actor_tid','actor_start')]
                if release and not release['context'] else None,
            release_context=('task','softirq','hardirq')[release['context']] if release else None,
            evidence='E2',packet_payload_owner='UNKNOWN',clone_lineage='UNOBSERVED',
            allocator_lock_holder=None,blocking_container=None,backend_cpu_ns=None,
            backend_scope='alloc_skb_fclone header and initial data allocation together; scheduling and IRQ included',
            release_scope='original skb release entry; not final fclone/data backend free'))
    # Original header lives cannot overlap at a recycled address.
    addresses=defaultdict(list)
    for e in episodes:
        if e['skb_address']: addresses[e['skb_address']].append(e)
    for lives in addresses.values():
        lives.sort(key=lambda e:e['begin_ns'])
        for a,b in zip(lives,lives[1:]):
            if a['release_entry_ns'] is None or a['release_entry_ns']>=b['begin_ns']:
                excluded['address_reuse_without_release']+=1
    accepted=quality['status']==scope['status']=='PASS'
    if excluded or not accepted or not supported: episodes=[]
    return dict(status='FAIL' if excluded else 'PASS' if supported and accepted else 'UNOBSERVED',
        episodes=episodes,excluded=dict(excluded),unknown=dict(unknown),
        limits=['TCP send original header allocation only, no receive or transformed skb lineage',
                'requester, socket creator, release executor and packet owner are different facts',
                'wall backend interval is not allocator-exclusive CPU, queue wait or a blocking relation',
                'release entry does not prove fclone or shared data are finally freed'])
