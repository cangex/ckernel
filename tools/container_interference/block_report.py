# SPDX-License-Identifier: GPL-2.0
"""Bounded native request episodes; sharing a device never identifies a blocker."""
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

from collector_audit import audit
from explain import explain, within_window
from owner_report import fields
from block_tag_report import tag_episodes
from block_merge_report import analyze_provenance
from writeback_report import analyze_writeback

REQUIRED = {'protocol','sample_time_ns','request','episode_ns','submitter_tid','submitter_start',
    'queue','bio','phase','dev_major','dev_minor','remaining','completed','operation','multi_bio',
    'context','status','actor_tid','actor_start','actor_id','actor_generation','cpu','stack_id'}
ORIGIN={'bio_cgroup','bio_owner_id','bio_owner_generation','bio_bytes','bio_origin_overdepth'}
ADMISSION={'admission','submitter_id','submitter_generation','submitter_flags'}


def actor(row):
    return tuple(row[k] for k in ('actor_id','actor_generation','actor_tid','actor_start'))


def submitter(row):
    scope=(row['submitter_id'],row['submitter_generation']) if row['protocol']==3 else (row['id'],row['generation'])
    return scope+(row['submitter_tid'],row['submitter_start'])


def episode(rows):
    start=rows[0]; problems=Counter(); uncertainty=Counter(); queued=None; issued=None
    queue_intervals=[]; service_intervals=[]; completions=[]; terminal=None; expected=None
    devices=set(); queues=set(); flags=set(); remapped=False; bio_origins=[]
    if start['phase']!=1 or start['sample_time_ns']!=start['episode_ns']:
        return None, {'missing_episode_start':1}
    initial_submitter=submitter(start)
    selection=(start['id'],start['generation'])
    for index,row in enumerate(rows):
        now=row['sample_time_ns']; phase=row['phase']
        devices.add((row['dev_major'],row['dev_minor'])); queues.add(row['queue']); flags.add(row['operation'])
        if terminal is not None: problems['event_after_terminal']+=1; continue
        if row['multi_bio']: uncertainty['multiple_bios']+=1
        if row['protocol']>=2:
            origin=(row['bio_owner_id'],row['bio_owner_generation'])
            bio_origins.append(dict(time_ns=now,bio=row['bio'],cgroup_id=row['bio_cgroup'],
                registered_container=list(origin) if all(origin) else None,bytes=row['bio_bytes'],
                phase=phase,request_remaining_bytes=row['remaining'],
                ancestor_overdepth=bool(row['bio_origin_overdepth'])))
            if not all(origin): uncertainty['head_bio_origin_unresolved']+=1
        if submitter(row)!=initial_submitter:
            problems['submitter_changed']+=1
        if (row['id'],row['generation'])!=selection or any(row.get(k)!=start.get(k) for k in ('admission','submitter_flags')):
            problems['admission_changed']+=1
        if phase==1:
            if index: problems['duplicate_start']+=1
        elif phase==2:
            if queued is not None or issued is not None: problems['insert_while_pending']+=1
            queued=now
        elif phase==3:
            if issued is not None: problems['duplicate_issue']+=1
            if queued is not None: queue_intervals.append([queued,now]); queued=None
            issued=now
            expected=row['remaining']
        elif phase==4:
            if issued is None: uncertainty['unobserved_issue_before_requeue']+=1
            else: service_intervals.append(dict(interval_ns=[issued,now],end='requeue')); issued=None
            expected=None
        elif phase==5:
            if row['completed']>row['remaining']: problems['completion_exceeds_remaining']+=1
            if expected is not None and row['remaining']!=expected:
                uncertainty['remaining_changed_without_observed_completion']+=1
            expected=row['remaining']-row['completed']
            completions.append(dict(time_ns=now,remaining_before=row['remaining'],bytes=row['completed'],
                status=row['status'],executor=list(actor(row)) if not row['context'] else None,
                context=('task','softirq','hardirq','nmi')[row['context']]))
            if row['remaining']==row['completed']:
                terminal=now
                if issued is None: uncertainty['unobserved_issue_before_completion']+=1
                else: service_intervals.append(dict(interval_ns=[issued,now],end='data_completion')); issued=None
        elif phase==6:
            terminal=now; uncertainty['merged_into_unobserved_survivor']+=1
            if issued is not None: problems['merge_while_issued']+=1
            if queued is not None:
                queue_intervals.append([queued,now]); queued=None
        elif phase==7:
            remapped=True; uncertainty['remapped_request']+=1
    if len(devices)>1 or len(queues)>1: uncertainty['route_changed']+=1
    if len(flags)>1: uncertainty['operation_changed']+=1
    if terminal is None: uncertainty['window_unclosed_request']+=1
    if queued is not None: uncertainty['unclosed_queue_interval']+=1
    if issued is not None: uncertainty['unclosed_execution_interval']+=1
    if problems: return None,dict(problems)
    return dict(request=start['request'],episode_ns=start['episode_ns'],submitter=list(initial_submitter),
        selected_container=list(selection),admission='bio_billing_root' if start.get('admission')==2 else 'submitter_root',
        submitter_kernel_thread=bool(start['submitter_flags'] & 0x00200000) if start['protocol']==3 else None,
        submitter_lifetime='start_epoch_unknown' if not start['submitter_start'] else 'observed_task_start',
        initial_dirtier=None,inode_owner=None,
        episode_interval_ns=[start['episode_ns'],terminal],terminal='merge_transfer' if rows[-1]['phase']==6 else
            'data_completion' if terminal is not None else 'UNOBSERVED',
        devices=[list(v) for v in sorted(devices)],queues=sorted(queues),initial_bytes=start['remaining'],
        initial_bio=start['bio'],operation=start['operation'],queue_intervals_ns=queue_intervals,
        service_intervals=service_intervals,completions=completions,uncertainty=dict(uncertainty),
        ownership='billing_scope_not_dirtier' if start.get('admission')==2 else
            'initial_submitter_only' if uncertainty or remapped else 'observed_request_submitter',
        head_bio_origins=bio_origins,origin_coverage='observed_head_bio_only' if bio_origins else 'HISTORICAL_NOT_RECORDED',
        blocking_container=None,causal='NOT_ESTABLISHED',evidence='E2',request_memory_free='UNOBSERVED'),{}


def analyze(record,raw):
    if record.get('collector')!='block' or len(raw)>16<<20: raise ValueError('bounded block capture required')
    base=explain(record,raw); scope=audit(record,raw); excluded=Counter(); groups=defaultdict(list); stacks={}
    identities=dict(record.get('root_identities',{})); identities.update(record.get('owner_identities',{}))
    known={(v['id'],v['generation']) for v in identities.values()}; count=0; stack_errors=Counter()
    for line in raw.decode().splitlines():
        item=json.loads(line); d=fields(item.get('detail',''))
        if item.get('kind')=='stack_symbols' and ' leaf_to_root=' in item.get('detail',''):
            stacks[d['stack_id']]=item['detail'].split(' leaf_to_root=',1)[1].split('>')
        if item.get('kind')!='BLOCK': continue
        count+=1
        if count>16384: excluded['report_capacity']+=1; continue
        required=REQUIRED | (ORIGIN if d.get('protocol') in (2,3) else set()) | (ADMISSION if d.get('protocol')==3 else set())
        if (not required<=d.keys() or any(type(d[k]) is not int or d[k]<0 for k in required-{'stack_id'})
                or d['stack_id'] < -4095 or d['protocol'] not in (1,2,3) or not 1<=d['phase']<=7
                or not 0<=d['context']<=3 or d['multi_bio'] not in (0,1)
                or not all(d[k] for k in ('request','episode_ns','queue','submitter_tid')) or
                not d['submitter_start'] and not (d['protocol']==3 and d['submitter_id']==0 and
                    d['submitter_generation']==0 and d['submitter_flags'] & 0x00200000)):
            excluded['schema']+=1; continue
        if d['protocol']>=2 and (d['bio_origin_overdepth'] not in (0,1) or
                (d['bio_owner_id'],d['bio_owner_generation'])!=(0,0) and
                ((d['bio_owner_id'],d['bio_owner_generation']) not in known or d['bio_origin_overdepth'])):
            excluded['bio_origin_identity']+=1; continue
        d.update(id=item.get('id'),generation=item.get('generation')); who=actor(d)
        if d['protocol']==3:
            source=(d['submitter_id'],d['submitter_generation']); selection=(d['id'],d['generation'])
            if (d['admission'] not in (1,2) or d['submitter_flags']>0xffffffff or
                    source!=(0,0) and source not in known or
                    d['admission']==1 and source!=selection or
                    d['phase']==1 and d['admission']==2 and
                    (source==selection or (d['bio_owner_id'],d['bio_owner_generation'])!=selection)):
                excluded['admission_identity']+=1; continue
        if ((d['id'],d['generation']) not in known or who[:2]!=(0,0) and who[:2] not in known
                or d['context'] and any(who) or not d['context'] and (not who[2] or
                    not who[3] and not (d['protocol']==3 and who[:2]==(0,0)))
                or d['phase']==1 and (d['context'] or who!=submitter(d))):
            excluded['identity']+=1; continue
        if not within_window(record,d['episode_ns'],d['sample_time_ns']): excluded['outside_window']+=1; continue
        key=(d['request'],d['episode_ns'])
        if key not in groups and len(groups)>=4096: excluded['episode_capacity']+=1; continue
        if d['stack_id']<0: stack_errors[str(d['stack_id'])]+=1
        groups[key].append(d)
    requests=[]; lifetimes=defaultdict(list)
    if not excluded and base['quality']['status']=='PASS' and scope['status']=='PASS':
        for key,rows in sorted(groups.items()):
            rows.sort(key=lambda r:r['sample_time_ns'])
            if len({r['protocol'] for r in rows})!=1:
                excluded['mixed_episode_protocol']+=1; continue
            result,problems=episode(rows); excluded.update(problems)
            if result:
                result['start_stack_leaf_to_root']=stacks.get(rows[0]['stack_id'],[])
                result['start_stack_error']=rows[0]['stack_id'] if rows[0]['stack_id']<0 else None
                requests.append(result); lifetimes[key[0]].append(result['episode_interval_ns'])
        for intervals in lifetimes.values():
            intervals.sort()
            if any(a[1] is None or a[1]>=b[0] for a,b in zip(intervals,intervals[1:])):
                excluded['request_address_reused_before_terminal']+=1
    tags,tag_defects=tag_episodes(record,raw)
    for tag in tags:
        tag['stack_leaf_to_root']=stacks.get(tag['stack_id'],[])
        tag['stack_error']=tag['stack_id'] if tag['stack_id']<0 else None
    excluded.update(tag_defects)
    provenance,provenance_defects=analyze_provenance(record,raw,groups)
    excluded.update(provenance_defects)
    writeback,writeback_defects=analyze_writeback(record,raw,requests)
    excluded.update(writeback_defects)
    if tags and 'block_tag' not in record.get('inventory',{}).get('program_names',[]):
        excluded['tag_missing_producer']+=1
    quality=dict(base['quality'])
    if excluded: quality.update(status='FAIL',defects=quality['defects']+list(excluded))
    if quality['status']!='PASS' or scope['status']!='PASS':
        requests=[]; tags=[]; provenance['issue_sources']=[]; provenance['merge_transfers']=[]
        writeback['contexts']=[]; writeback['request_links']=[]; writeback['dirty_observations']=[]
    else:
        victims={tuple(link['victim']):link for link in provenance['merge_transfers']
                 if link['state']=='OBSERVED_TRANSFER'}
        for req in requests:
            link=victims.get((req['request'],req['episode_ns']))
            if link:
                req['merge_survivor']=link['survivor']
                req['uncertainty'].pop('merged_into_unobserved_survivor',None)
    return dict(schema='cis-block-report-v1',boot_id=record.get('boot_id'),session_id=record.get('session_id'),
        quality=quality,scope_audit=scope,requests=requests,tag_waits=tags,provenance=provenance,writeback=writeback,
        tag_coverage='AVAILABLE' if 'block_tag' in record.get('inventory',{}).get('program_names',[]) else 'HISTORICAL_NOT_RECORDED',
        excluded=dict(excluded),stack_capture_errors=dict(stack_errors),
        raw_sha256=hashlib.sha256(raw).hexdigest(),source=base['source'],
        analysis_source_sha256=dict(base['analysis_source_sha256'],**{name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in ('block_report.py','block_tag_report.py','block_merge_report.py','writeback_report.py')}),
        performance_certification='NOT_ACCEPTED',limits=[
            'initial request submitter is not an exclusive owner of merged bios or writeback work',
            'bio billing-root admission preserves the real submitter; initial dirtier and inode owner are not inferred',
            'early unregistered kernel tasks may have start epoch zero; their TID is not joined across request episodes',
            'device overlap identifies neither a holder nor a blocking container',
            'tag slowpath excludes immediate successes and does not identify slot holders; TAG_FOUND can still be rejected by inactive hctx',
            'tag io_schedule intervals include wakeup/scheduling and probe overhead, not exclusive device delay or spin cycles',
            'tag pool address is an episode-local route, not a proven lifetime; scheduler/device internal queues not covered',
            'merge links require observed episodes; bio blkcg byte weights are issue-local, not exclusive ownership; partial completion is not request memory release',
            'queue and execution intervals are wall time, not CPU cycles or exclusive delay causes',
            'E3 requires a separately controlled counterfactual; this report provides none'])
