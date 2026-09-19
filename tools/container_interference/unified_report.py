#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Normalize facts without summing overlapping time or upgrading evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path

from explain import explain
from collector_audit import audit

MAX_RELATIONS=128


def analyze(record,raw):
    collector=record['collector']; base=explain(record,raw); relations=[]; omitted=0
    specialist=None
    if collector in ('sync','counter','allocator','net','block','rwsem'):
        module=__import__(collector+'_report'); specialist=module.analyze(record,raw)
    quality=specialist['quality'] if specialist else base['quality']
    scope=specialist['scope_audit'] if specialist else audit(record,raw)
    if scope['status']!='PASS':
        quality=dict(quality,status='FAIL' if 'FAIL' in (quality['status'],scope['status']) else 'BLOCKED',
            defects=quality['defects']+['collector_scope_'+scope['status'].lower()])
    if collector=='allocator' and specialist['lifetimes']['status']=='FAIL':
        quality=dict(quality,status='FAIL',defects=quality['defects']+['allocation_lifetime_invalid'])

    def add(kind,level,actor,resource,participants,interval,chain,unknown,**detail):
        nonlocal omitted
        if len(relations)>=MAX_RELATIONS: omitted+=1; return
        relations.append(dict(relation=kind,evidence=level,affected_actor=actor,resource=resource,
            participants=participants,interval_ns=interval,chain_leaf_to_root=chain,unknown=unknown,
            causal='NOT_ESTABLISHED',details=detail))

    if quality['status']=='PASS' and scope.get('status','PASS')=='PASS':
        if collector in ('ip','owner','fd','slub','sched','reclaim'):
            for f in base['findings']:
                if f['kind']=='observed_holder_waiter':
                    add('holder_waiter','E2',f['waiter'],dict(kind=f['resource'],address=f['object']),
                        [f['holder']], [f['wait_begin_ns'],f['wait_end_ns']],f.get('waiter_stack_leaf_to_root',[]),
                        ['overlap is not total throughput causality'],source_finding=f)
                else:
                    add(f.get('observation',f['kind']),f.get('evidence','E1'),[f.get('id'),f.get('generation')],
                        dict(kind=f.get('observation',f['kind'])),[],f.get('interval_ns'),f.get('stack_leaf_to_root',[]),
                        ['external pressure producer not identified'],source_finding=f)
        elif collector=='sync':
            for f in specialist['candidates']:
                add('wait_interval_only','E1',[f['container_id'],f['generation'],f['task_id']],
                    dict(kind=f['access_class'],address=f['address'],lifetime='UNKNOWN'),[],f['interval_ns'],
                    f['stack_leaf_to_root'],['holder and complete lifetime unknown'],outcome=f['outcome'])
        elif collector=='counter':
            for f in specialist['shared_objects']:
                add('shared_updates','E2',None,dict(kind='page_counter',address=f['address'],generation=f['object_generation'],field=f['field']),
                    f['actors'],None,[],['no mutex-style holder; cache-line contention unverified'])
            for f in specialist['calls']:
                add('counter_operation','E1',f['actor'],dict(kind='page_counter',address=f['leaf_address'],generation=f['leaf_generation']),
                    [],f['interval_ns'],f['stack_leaf_to_root'],['wall time includes observer and scheduling'],
                    outcome=f['outcome'],steps=f['steps'])
        elif collector=='allocator':
            for f in specialist['calls']:
                unknown=['Maple tree owner and SLUB lock holder not inferred']
                if f['allocation_stack_status']!='AVAILABLE':
                    unknown.append('allocation calling path unavailable; typed stages do not replace a stack')
                add('allocation_stages','E1',f['actor'],dict(kind='selected_cache',address=f['cache_address'],lifetime='UNKNOWN'),
                    [],f['interval_ns'],f['stack_leaf_to_root'],unknown,
                    phases=f['phases'],exclusive_wall_ns=f['exclusive_wall_ns'],outcome=f['returned_count'],
                    allocation_stack_status=f['allocation_stack_status'],allocation_stack_error=f['allocation_stack_error'])
            for f in specialist['lifetimes']['release_entries']:
                add('allocation_release_entry','E2',f['allocation_requester'],
                    dict(kind='observed_allocation',address=f['object_address'],observation_key=f['observation_key']),[],
                    [f['allocation_time_ns'],f['release_entry_ns']],f['release_stack_leaf_to_root'],
                    ['release entry is not backend completion or memcg billing'],release_executor=f['release_executor'])
        elif collector=='net':
            for sock in specialist['sockets']:
                resource=dict(kind='tcp_socket',cookie=sock['cookie'],netns=sock['netns'])
                for name in ('creation_observation','accept_observation'):
                    fact=sock[name]
                    if fact:
                        add('socket_'+name,fact['evidence'],fact['actor'],resource,[],
                            [fact['time_ns'],fact['time_ns']],[],
                            ['creator/acceptor is not a permanent owner, current holder or unique blocker'],
                            boundary=fact['boundary'])
                for f in sock['waits']:
                    known=[h['holder'] for h in f['observed_holders'] if h['evidence']=='E2' and h['holder']]
                    unknown=['logical ownership wait; not slock spin cycles']
                    if len(known)!=len(f['observed_holders']):
                        unknown.append('some observed holders have unknown container identity')
                    add('socket_holder_waiter','E2' if known else 'E1',f['waiter'],resource,
                        known,f['interval_ns'],f['stack_leaf_to_root'],unknown,
                        observed_holders=f['observed_holders'],unexplained_wait_ns=f['unexplained_wait_ns'])
                for f in sock['backlog']:
                    add('backlog_service_release','E2',None,dict(resource,skb=f['skb_address'],queue_epoch_ns=f['queue_epoch_ns']),[],
                        [f['queue_epoch_ns'],f['release_entry_ns']],[],['packet origin and unique blocker unknown'],queue_episode=f)
        elif collector=='rwsem':
            for obj in specialist['objects']:
                for f in obj['waits']:
                    known=[h['holder'] for h in f['observed_holders'] if h['evidence']=='E2']
                    add('rwsem_holder_waiter','E2' if known else 'E1',f['waiter'],
                        dict(kind='rw_semaphore',address=obj['address'],init_ns=obj['init_ns'],lifetime=obj['lifetime']),
                        known,f['interval_ns'],f['stack_leaf_to_root'],
                        ['observed reader set is not complete; elapsed time is not spin cycles'],
                        observed_holders=f['observed_holders'],mode=f['mode'],outcome=f['outcome'],
                        unexplained_elapsed_ns=f['unexplained_elapsed_ns'])
        elif collector=='block':
            bio_sources={}; merge_transfers={}
            for row in specialist.get('provenance',{}).get('issue_sources',[]):
                bio_sources.setdefault((row['request'],row['episode_ns']),[]).append(row)
            for row in specialist.get('provenance',{}).get('merge_transfers',[]):
                merge_transfers.setdefault(tuple(row['survivor']),[]).append(row)
            for f in specialist['tag_waits']:
                add('block_tag_wait','E1',f['container']+[f['tid'],f['task_start']],
                    dict(kind='tag_allocation_episode',queue=f['queue'],pools=f['pools'],episode_ns=f['episode_ns']),
                    [],f['interval_ns'],f['stack_leaf_to_root'],
                    ['slot holders unknown; elapsed sleep includes scheduler and probe cost; TAG_FOUND is not I/O success'],
                    sleep_intervals=f['sleep_intervals'],outcome=f['outcome'],identity_changes=f['identity_changes'])
            for f in specialist['requests']:
                add('block_request_episode','E2',f['submitter'],dict(kind='observed_request',address=f['request'],episode_ns=f['episode_ns']),
                    [],f['episode_interval_ns'],f['start_stack_leaf_to_root'],
                    ['initial submitter is not a merge/writeback owner; device peers are not proven blockers'],
                    devices=f['devices'],queue_intervals_ns=f['queue_intervals_ns'],service_intervals=f['service_intervals'],
                    head_bio_origins=f['head_bio_origins'],origin_coverage=f['origin_coverage'],
                    issue_bio_sources=bio_sources.get((f['request'],f['episode_ns']),[]),
                    merge_transfers=merge_transfers.get((f['request'],f['episode_ns']),[]),
                    uncertainty=f['uncertainty'],terminal=f['terminal'])
    result=dict(schema='cis-explanation-v2',boot_id=record.get('boot_id'),session_id=record['session_id'],collector=collector,
        window=record.get('window'),quality=quality,scope_audit=scope,relations=relations,omitted_relations=omitted,
        raw_sha256=hashlib.sha256(raw).hexdigest(),source=base['source'],
        analysis_source_sha256=dict(specialist['analysis_source_sha256'] if specialist else base['analysis_source_sha256'],
            **{name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
               for name in ('unified_report.py','collector_audit.py','collector_manifest.py')}),
        specialist=specialist,base=base,total_interference_ns=None,performance_certification='NOT_ACCEPTED',
        timing=dict(periodic_wait_ns='NOT_INFERRED',specialist_queue_wait_ns=(record.get('scheduled') or {}).get('diagnosis',{}).get('queue_wait_ns'),
            explanation_lag_ns=base['explanation_lag_ns'],sample_age_at_specialist_admit_ns=(record.get('scheduled') or {}).get('diagnosis',{}).get('sample_age_ns')),
        limits=['different relation types cannot be added into total interference',
            'resource address must not be joined across boot/session without verified lifetime',
            'empty findings or rejected quality do not prove interference absent',
            'this report does not infer E3 from any hotspot or interval overlap'])
    return result


def markdown(report):
    labels={'holder_waiter':'持有与等待','wait_interval_only':'锁等待，持有者未闭合','shared_updates':'共同更新同一计数器',
        'counter_operation':'计数更新/回滚','allocation_stages':'对象分配阶段','allocation_release_entry':'分配与释放入口',
        'socket_holder_waiter':'Socket逻辑锁等待','backlog_service_release':'backlog排队、服务与释放',
        'block_request_episode':'块请求排队与服务','block_tag_wait':'块请求槽位等待','rwsem_holder_waiter':'读写锁已观察持有与等待'}
    lines=['# 容器周期Profile解释报告','','会话 `%s`，专项 `%s`，证据质量 **%s**。'%(report['session_id'],report['collector'],report['quality']['status']),
        '这是受限路径上的观察报告，不是总干扰率或生产性能认证。','','## 已观察关系']
    for r in report['relations'][:16]:
        lines.append('- **%s / %s**：任务 `%s`，资源 `%s`；参与者 `%s`。'%(labels.get(r['relation'],r['relation']),r['evidence'],
            r['affected_actor'],json.dumps(r['resource'],ensure_ascii=False),r['participants']))
        if r['chain_leaf_to_root']: lines.append('  调用栈（叶到根）：`%s`。'%' → '.join(r['chain_leaf_to_root']))
        if r['relation']=='block_request_episode':
            snapshots=r['details'].get('issue_bio_sources',[])
            for snap in snapshots[:4]:
                lines.append('  下发时剩余 %d 字节；bio计费来源 %s；未知 %d 字节。重排队快照不累加为新请求量。'%(
                    snap['remaining_bytes'],json.dumps(snap['sources'],ensure_ascii=False),snap['unknown_bytes']))
            if len(snapshots)>4: lines.append('  其余下发快照见JSON。')
            if r['details'].get('merge_transfers'):
                lines.append('  观察到 %d 次原生合并转移；这不表示设备存在唯一阻塞容器。'%len(r['details']['merge_transfers']))
    if not report['relations']: lines.append('本窗口未形成可接收的关系；不能据此认定不存在干扰。')
    lines+=['','## 边界','共享计数器、队列参与者和锁持有者是不同关系。不能把其中任意一种直接称为唯一阻塞方。',
        '候选产生前的周期等待、专项排队时间和解释耗时分别记录，不混为异常发现延迟。',
        '完整关系、未知项、采样限制及原始证据哈希见JSON。']
    return '\n'.join(lines)+'\n'


if __name__=='__main__':
    os.umask(0o077)
    p=argparse.ArgumentParser(); p.add_argument('record',type=Path); p.add_argument('raw',type=Path); p.add_argument('output',type=Path)
    args=p.parse_args()
    if args.record.stat().st_size>16<<20 or args.raw.stat().st_size>16<<20: raise ValueError('bounded inputs required')
    report=analyze(json.loads(args.record.read_text()),args.raw.read_bytes())
    args.output.mkdir(mode=0o700)
    (args.output/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2))
    (args.output/'report.md').write_text(markdown(report))
    print(json.dumps(dict(quality=report['quality']['status'],relations=len(report['relations']),omitted=report['omitted_relations'])))
