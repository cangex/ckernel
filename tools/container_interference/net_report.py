# SPDX-License-Identifier: GPL-2.0
"""Observed socket ownership, queue residence and release, never packet-owner inference."""
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

from collector_audit import audit
from explain import explain, within_window
from owner_report import fields
from net_tx_report import correlate as tx_correlate

REQUIRED={'protocol','sample_time_ns','cookie','socket','skb','queue_ns','phase','context',
          'actor_tid','actor_start','actor_id','actor_generation','cpu','netns','bytes',
          'backlog_bytes','packet_flags','stack_id'}


def actor(row):
    return tuple(row[k] for k in ('actor_id','actor_generation','actor_tid','actor_start'))


def ownership(rows):
    held=None; holds=[]; waiting={}; waits=[]; unknown=Counter(); bad=False
    for row in rows:
        phase=row['phase']; who=actor(row); now=row['sample_time_ns']
        if phase>5: continue
        if row['context'] or not who[2] or not who[3]:
            bad=True; unknown['unsupported_lock_context']+=1; continue
        if phase==1:
            if who in waiting: bad=True; unknown['duplicate_wait']+=1
            else: waiting[who]=row
        elif phase in (2,4):
            if held is not None: bad=True; unknown['overlapping_holders']+=1
            held=row
            start=waiting.pop(who,None)
            if start:
                if phase==4: bad=True; unknown['fast_acquire_after_logical_wait']+=1
                else: waits.append((start,row))
        else:
            if held is None: unknown['unobserved_acquire']+=1; continue
            if actor(held)!=who or (held['phase'],phase) not in ((2,3),(4,5)):
                bad=True; unknown['release_mismatch']+=1; held=None; continue
            holds.append((held,row)); held=None
    if held is not None: unknown['unclosed_hold']+=1
    unknown['unclosed_wait']+=len(waiting)
    intervals=[]
    if not bad:
        for begin,end in waits:
            lo,hi=begin['sample_time_ns'],end['sample_time_ns']; overlaps=[]
            for acquire,release in holds:
                left=max(lo,acquire['sample_time_ns']); right=min(hi,release['sample_time_ns'])
                if left>=right or actor(acquire)==actor(begin): continue
                certain=all(actor(acquire)) and all(actor(begin))
                overlaps.append(dict(holder=list(actor(acquire)) if certain else None,
                    interval_ns=[left,right],evidence='E2' if certain else 'E1',
                    relation_scope='cross_container' if certain and actor(acquire)[:2]!=actor(begin)[:2]
                        else 'same_container' if certain else 'unknown_container',
                    holder_acquire_ns=acquire['sample_time_ns'],holder_release_ns=release['sample_time_ns']))
            intervals.append(dict(waiter=list(actor(begin)),interval_ns=[lo,hi],wall_ns=hi-lo,
                observed_holders=overlaps,unexplained_wait_ns=hi-lo-sum(v['interval_ns'][1]-v['interval_ns'][0] for v in overlaps),
                stack_id=begin['stack_id'],spin_cycles=None,causal='NOT_ESTABLISHED'))
    return intervals,dict(unknown),bad


def queues(rows):
    groups=defaultdict(list); unknown=Counter(); results=[]; bad=False
    for row in rows:
        if not 6<=row['phase']<=9: continue
        if not row['skb'] or not row['queue_ns']:
            bad=True; unknown['missing_queue_instance']+=1; continue
        groups[(row['skb'],row['queue_ns'])].append(row)
    if len(groups)>4096: return [],{'queue_report_capacity':len(groups)},True
    for (address,epoch),events in groups.items():
        by_phase=defaultdict(list)
        for row in events: by_phase[row['phase']].append(row)
        if len(by_phase[6])!=1 or any(len(v)>1 for v in by_phase.values()):
            bad=True; unknown['duplicate_or_missing_queue']+=1; continue
        q=by_phase[6][0]; start=(by_phase[7] or [None])[0]; end=(by_phase[8] or [None])[0]; free=(by_phase[9] or [None])[0]
        if epoch!=q['sample_time_ns'] or any(r['sample_time_ns']<epoch for r in events):
            bad=True; unknown['queue_time_order']+=1; continue
        if end and (not start or actor(start)!=actor(end) or start['context']!=end['context'] or
                    start['sample_time_ns']>end['sample_time_ns']):
            bad=True; unknown['service_pair']+=1; continue
        if free and start and free['sample_time_ns']<start['sample_time_ns']:
            bad=True; unknown['service_after_free']+=1; continue
        if not start: unknown['no_service_start']+=1
        if start and not end: unknown['unclosed_service']+=1
        if not free: unknown['unobserved_release']+=1
        results.append(dict(skb_address=address,queue_epoch_ns=epoch,evidence='E2',
            queue_executor=list(actor(q)) if q['context']==0 else None,
            queue_context=('task','softirq','hardirq')[q['context']],
            packet_origin='UNKNOWN',data_buffer_owner='UNKNOWN',packet_flags=q['packet_flags'],
            service_executor=list(actor(start)) if start and start['context']==0 else None,
            queued_bytes=q['bytes'],backlog_bytes_before_length_update=q['backlog_bytes'],
            residence_ns=start['sample_time_ns']-epoch if start else None,
            service_interval_ns=[start['sample_time_ns'],end['sample_time_ns']] if start and end else None,
            release_entry_ns=free['sample_time_ns'] if free else None,
            release_executor=list(actor(free)) if free and free['context']==0 else None,
            release_context=('task','softirq','hardirq')[free['context']] if free else None,
            release_complete='UNOBSERVED',blocking_container=None))
    return results,dict(unknown),bad


def provenance(rows):
    result=dict(creation_owner='UNOBSERVED',creation_observation=None,accept_observation=None)
    for phase,field in ((10,'creation_observation'),(11,'accept_observation')):
        found=[r for r in rows if r['phase']==phase]
        if len(found)>1:
            return result,True
        if not found: continue
        row=found[0]; who=actor(row)
        if row['context'] or any(row[k] for k in ('skb','queue_ns','bytes','packet_flags')):
            return result,True
        identity=list(who) if all(who) else None
        result[field]=dict(actor=identity,time_ns=row['sample_time_ns'],
            evidence='E2' if identity else 'E1',
            boundary='protocol_and_LSM_create_succeeded' if phase==10 else 'user_accept_operation_succeeded',
            scope='observed task, not memcg billing owner or permanent exclusive user')
        if phase==10 and identity: result['creation_owner']=identity
    # A passive TCP child is not the userspace-created listening socket.
    if result['creation_observation'] and result['accept_observation']:
        return result,True
    return result,False


def analyze(record,raw):
    if record.get('collector')!='net' or len(raw)>16<<20: raise ValueError('bounded net capture required')
    base=explain(record,raw); scope=audit(record,raw); excluded=Counter(); groups=defaultdict(list); stacks={}; stack_errors=Counter()
    identities=dict(record.get('root_identities',{})); identities.update(record.get('owner_identities',{}))
    known={(v['id'],v['generation']) for v in identities.values()}
    count=0
    for line in raw.decode().splitlines():
        item=json.loads(line); d=fields(item.get('detail',''))
        if item.get('kind')=='stack_symbols' and ' leaf_to_root=' in item.get('detail',''):
            stacks[d['stack_id']]=item['detail'].split(' leaf_to_root=',1)[1].split('>')
        if item.get('kind')!='NET': continue
        count+=1
        if count>16384: excluded['report_capacity']+=1; continue
        if (not REQUIRED<=d.keys() or any(type(d[k]) is not int or d[k]<0 for k in REQUIRED-{'stack_id'})
                or type(d['stack_id']) is not int or d['stack_id'] < -4095
                or d['protocol']!=1 or not 1<=d['phase']<=11 or d['context'] not in (0,1,2)
                or not d['cookie'] or not d['socket'] or not d['netns'] or d['packet_flags'] & ~7):
            excluded['schema']+=1; continue
        who=actor(d)
        if ((item.get('id'),item.get('generation')) not in known
                or who[:2]!=(0,0) and who[:2] not in known
                or d['context'] and any(who) or not d['context'] and not all(who[2:])):
            excluded['identity']+=1; continue
        if not within_window(record,d['sample_time_ns'],d['sample_time_ns']):
            excluded['outside_window']+=1; continue
        if d['cookie'] not in groups and len(groups)>=64: excluded['watch_capacity']+=1; continue
        if d['stack_id']<0: stack_errors[str(d['stack_id'])]+=1
        groups[d['cookie']].append(d)
    accepted=not excluded and base['quality']['status']=='PASS' and scope['status']=='PASS'
    sockets=[]
    if accepted:
        for cookie,rows in sorted(groups.items()):
            rows.sort(key=lambda r:r['sample_time_ns'])
            if len({(r['socket'],r['netns']) for r in rows})!=1:
                excluded['cookie_identity_changed']+=1; continue
            waits,owner_unknown,owner_bad=ownership(rows)
            backlog,queue_unknown,queue_bad=queues(rows)
            origins,origin_bad=provenance(rows)
            if owner_bad or queue_bad or origin_bad:
                excluded['socket_stream_invalid']+=1
            for wait in waits:
                stack_id=wait.pop('stack_id')
                wait['stack_leaf_to_root']=stacks.get(stack_id,[])
                wait['stack_capture_error']=stack_id if stack_id<0 else None
                wait['stack_status']='AVAILABLE' if wait['stack_leaf_to_root'] else 'UNAVAILABLE'
            sockets.append(dict(cookie=cookie,socket_address=rows[0]['socket'],netns=rows[0]['netns'],
                **origins,
                lifetime='native_socket_cookie',waits=waits if not owner_bad else [],
                backlog=backlog if not queue_bad else [],owner_unknown=owner_unknown,queue_unknown=queue_unknown,
                observed_actors=[list(a) for a in sorted({actor(r) for r in rows if all(actor(r))})]))
    quality=dict(base['quality'])
    if excluded: quality.update(status='FAIL',defects=quality['defects']+list(excluded))
    tx=tx_correlate(record,raw,quality,scope)
    if tx['status']=='FAIL': quality.update(status='FAIL',defects=quality['defects']+['net_tx_invalid'])
    if quality['status']!='PASS' or scope['status']!='PASS': sockets=[]
    return dict(schema='cis-net-report-v1',boot_id=record.get('boot_id'),session_id=record.get('session_id'),
        quality=quality,scope_audit=scope,sockets=sockets,tx=tx,excluded=dict(excluded),stack_capture_errors=dict(stack_errors),
        raw_sha256=hashlib.sha256(raw).hexdigest(),source=base['source'],
        analysis_source_sha256=dict(base['analysis_source_sha256'],**{name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in ('net_report.py','net_tx_report.py')}),
        performance_certification='NOT_ACCEPTED',
        limits=['logical lock wait is wall time, not slock spin cycles',
                'window-before or unclosed holders remain unknown',
                'queue association is not packet creation or sender ownership',
                'skb release entry is not complete backend cost; clone/GSO data ownership unproven',
                'same socket time overlap supports E2, not a unique throughput cause',
                'socket cookie generation and non-target release hook work are not free'])
