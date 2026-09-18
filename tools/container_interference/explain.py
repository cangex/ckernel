#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Bounded offline session explanations, not automatic root-cause certification."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from owner_report import analyze as owner_analyze, fields
from session_quality import assess
from attribution import classify

MAX_BYTES = 16*1024*1024
MAX_FINDINGS = 128


def within_window(record, begin, end):
    window = record.get('window') or {}
    lo, hi = window.get('start_ns'), window.get('end_ns')
    return (all(type(v) is int for v in (lo, hi, begin, end)) and
            lo <= begin <= end <= hi and lo < hi)


def explain(record, raw):
    if len(raw) > MAX_BYTES:
        raise ValueError('raw explanation input exceeds session limit')
    sid = str(record['session_id'])
    events = []
    for line in raw.decode('utf-8', errors='strict').splitlines():
        if len(line.encode()) > 8192:
            raise ValueError('oversize raw event')
        event = json.loads(line)
        if not isinstance(event, dict) or str(event.get('session_id')) != sid:
            raise ValueError('missing or cross-session event identity')
        events.append(event)
    quality = assess(record)
    if record.get('finalized') is not True:
        quality = dict(quality, status='BLOCKED', missing=quality['missing']+['durable_finalization'])
    loss = any(e.get('kind') in ('buffer_loss', 'sample_schema_error', 'owner_gap',
                               'entry_budget_disable', 'incomplete_scan_limited') for e in events)
    if loss:
        quality = dict(quality, status='FAIL', defects=quality['defects']+['raw_quality_event'])
    findings, candidates, unknown = [], [], []
    identities = dict(record.get('root_identities', {}))
    identities.update(record.get('owner_identities', {}))
    known = {(v['id'], v['generation']) for v in identities.values()}
    owner = None
    if record.get('collector') == 'owner':
        if any(fields(e['detail']).get('resource') not in (1, 2) for e in events if e.get('kind') == 'OWNER'):
            raise ValueError('unsupported owner resource protocol')
        owner = owner_analyze(events)
        for edge in owner['edges']:
            valid = quality['status'] == 'PASS' and edge['level'] == 'E2'
            valid &= tuple(edge['waiter'][:2]) in known and tuple(edge['holder'][:2]) in known
            valid &= within_window(record, edge['wait_begin_ns'], edge['wait_end_ns'])
            if not valid:
                unknown.append(dict(reason='ownership_quality_or_identity_incomplete', object=edge['object']))
                continue
            findings.append(dict(kind='observed_holder_waiter', evidence='E2', **edge))
        if owner['incomplete_intervals']:
            unknown.append(dict(reason='unclosed_owner_intervals', count=owner['incomplete_intervals']))
        if owner['bounded_prefix_limits']:
            unknown.append(dict(reason='bounded_owner_prefix', count=owner['bounded_prefix_limits']))
    for event in events:
        if event.get('kind') in ('E1', 'incomplete'):
            item = classify(event)
            detail = fields(event.get('detail', ''))
            begin, duration = detail.get('sample_time_ns'), detail.get('duration_ns')
            valid_interval = (type(begin) is int and type(duration) is int and duration >= 0 and
                              within_window(record, begin, begin+duration))
            if (quality['status'] != 'PASS' or (event.get('id'), event.get('generation')) not in known
                    or event.get('kind') == 'incomplete' or not valid_interval
                    or item.get('observation') == 'unsupported'):
                unknown.append(dict(reason='interval_quality_or_identity_incomplete', observation=item))
            else:
                findings.append(dict(kind='observed_interval', **item))
    for target, row in record.get('survey', {}).get('roots', {}).items():
        candidates.append(dict(target=target, kind='hotspot_and_pressure_only',
            valid=row.get('valid', False) and quality['status']=='PASS',
            top_ip=row.get('top_ip', []), rates=row.get('rates', {}),
            changes=row.get('reasons', []), status=row.get('status'),
            statement='hot IP or pressure change does not identify a competing owner'))
        cpu = row.get('counters', {}).get('files', {}).get('cpu.stat', {})
        if (quality['status']=='PASS' and row.get('valid') and
                cpu.get('delta', {}).get('nr_throttled', 0)>0):
            findings.append(dict(kind='cpu_throttling_counter', target=target, evidence='E1-counter',
                delta=cpu['delta'], intervals=cpu['read_intervals_ns'],
                scope='boundary snapshot includes prepare/drain, not an exact request or perf window',
                cause='quota event observed; external container not identified'))
    if not events:
        unknown.append(dict(reason='no_raw_events'))
    return dict(schema='cis-explanation-v1', session_id=sid, collector=record.get('collector'),
        source=record.get('source_identity'), raw_sha256=hashlib.sha256(raw).hexdigest(),
        window=record.get('window'), admission_policy=record.get('admission_policy', 'strict'),
        quality=quality, findings=findings[:MAX_FINDINGS], candidates=candidates,
        unknown=unknown[:MAX_FINDINGS], finding_count=len(findings),
        omitted_findings=max(0,len(findings)-MAX_FINDINGS), unknown_count=len(unknown),
        raw_counts=dict(Counter(e.get('kind', 'unknown') for e in events)),
        performance_certification='NOT_ACCEPTED', total_interference_ns=None,
        business_loss_causality=False,
        limits=['sampling absence is not absence of interference',
                'hold/wait and holder off-CPU overlap; never add as disjoint time',
                'bounded supported paths only; no full-kernel recall claim'])


def markdown(report):
    lines=['# 容器干扰观察报告', '',
           '会话：`%s`；采集类型：`%s`。'%(report['session_id'],report['collector']),
           '证据质量：**%s**；性能认证：**未通过认证**。'%report['quality']['status'], '',
           '## 观察到的事实']
    for item in report['findings']:
        if item['kind']=='observed_holder_waiter':
            w,h=item['waiter'],item['holder']
            relation='容器内部' if item['relation']=='container_internal' else '跨容器'
            lines.append('- %s关系：`%s:%s` 的线程 `%s` 等待 `%s` 对象 `%s`；与 `%s:%s` 的线程 `%s` 持有该对象的区间重合 %.3f ms。'%(
                relation,w[0],w[1],w[2],item['resource'],item['object'],h[0],h[1],h[2],item['overlap_ns']/1e6))
            chain=item.get('waiter_stack_leaf_to_root')
            lines.append('  等待栈（叶到根）：`%s`。'%(' → '.join(chain) if chain else '未完成符号解析，原始地址见JSON'))
            if item['holder_offcpu']:
                lines.append('  持有者存在已观察到的离开CPU片段；不能全部解释为自旋，也不能据此确定抢占者。')
        elif item['kind']=='cpu_throttling_counter':
            lines.append('- `%s` 出现CPU配额节流；证据是边界计数，不表示另一个容器持锁。'%item['target'])
        else:
            lines.append('- `%s`：观察到 `%s`，字段和调用栈索引见JSON；尚未识别阻塞方。'%(item.get('id'),item.get('observation')))
    if not report['findings']:
        lines.append('本窗口没有形成可验证的等待/持有者关系；不能据此认定没有干扰。')
    lines += ['', '## 热点与候选']
    for row in report['candidates']:
        lines.append('- `%s`：%s；热点 `%s`。这些仅是定位线索，不是根因结论。'%(row['target'],row['status'],
                     ', '.join(x.get('symbol','unknown') for x in row['top_ip'])))
    if not report['candidates']:lines.append('本会话未提供有效热点候选。')
    lines += ['', '## 未知与边界',
              '未闭合或未知记录：%s；省略展示的关系：%s。完整证据见JSON。'%(report['unknown_count'],report['omitted_findings']),
              '这里只解释支持路径上实际观察到的关系，不推算总干扰率，也不归因全部业务吞吐损失。',
              '证据哈希：`%s`。'%report['raw_sha256'], '']
    return '\n'.join(lines)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--record', type=Path, required=True)
    parser.add_argument('--events', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args=parser.parse_args()
    if args.record.stat().st_size>MAX_BYTES or args.events.stat().st_size>MAX_BYTES:
        raise ValueError('bounded inputs required')
    result=explain(json.loads(args.record.read_text()),args.events.read_bytes())
    for suffix,body in [('.json',json.dumps(result,ensure_ascii=False,indent=2)),('.md',markdown(result))]:
        with args.output.with_suffix(suffix).open('x') as stream:stream.write(body+'\n')
