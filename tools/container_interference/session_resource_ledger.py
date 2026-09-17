#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Version-bound partial resource ledger, without adding overlapping charges.

Missing backend/JIT/verifier bounds deliberately prevent total-memory approval.
Process CPU excludes callbacks and BPF running in business contexts.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

from session_check import extract
from p1_admission_check import records, source_identity


def analyze(text):
    files = extract(text)
    rows = []
    for record in records(text):
        sid = str(record['session_id'])
        logs = [body for name, body in files.items() if name.endswith('/records/'+sid+'.jsonl')]
        inventories, stages, errors = [], [], []
        if len(logs) != 1:
            errors.append('one raw session event file required')
        for line in logs[0].splitlines() if len(logs) == 1 else ():
            try:
                event = json.loads(line)
            except ValueError:
                errors.append('malformed raw event'); continue
            if str(event.get('session_id')) != sid:
                errors.append('event session mismatch'); continue
            fields = dict(re.findall(r'(\w+)=([^ ;]+)', event.get('detail', '')))
            if event.get('kind') == 'kernel_memory_inventory':
                inventories.append(fields)
            elif event.get('kind') == 'owner_entry_stages':
                stages.append(fields)
        receipt = record.get('receipt') or {}
        cpu = {key: record.get(key) for key in ('controller_cpu_ns', 'reaped_children_cpu_ns',
               'observer_process_cpu_ns', 'process_cpu_to_report_ns', 'process_cpu_to_publish_ns')}
        cpu['worker_subset_ns'] = receipt.get('cpu_ns')
        if all(type(cpu[k]) is int for k in ('controller_cpu_ns','reaped_children_cpu_ns','observer_process_cpu_ns')):
            if cpu['controller_cpu_ns']+cpu['reaped_children_cpu_ns'] != cpu['observer_process_cpu_ns']:
                errors.append('process CPU identity mismatch')
        else:
            errors.append('process CPU components missing')
        rows.append(dict(session_id=sid, nonce=record.get('nonce'), collector=record.get('collector'),
                         source=source_identity(record.get('source_identity') or record),
                         result=record.get('result'), cpu=cpu,
                         process_budget=record.get('process_cpu_budget'),
                         memory=dict(combined_rss_sampled_peak_bytes=record.get('combined_rss_peak_bytes'),
                                     worker_maxrss_kib=receipt.get('maxrss_kib'), inventories=inventories,
                                     total_upper_bound_bytes=None, total_complete=False),
                         owner_entry_stages=stages, quality_errors=errors))
    return dict(schema='cis-session-resource-ledger-v1',
                raw_sha256=hashlib.sha256(text.encode()).hexdigest(), sessions=rows,
                status='BLOCKED', budget_bytes=64*1024*1024,
                missing=['BPF/JIT/BTF/verifier temporary and deferred allocation upper bounds',
                         'perf object metadata, shared-page accounting and unsampled memory peaks',
                         'observer-attributable in-business-context and asynchronous kernel CPU',
                         'post-publication fixed-tail cleanup CPU and retained-memory accounting'],
                nonadditive=['worker CPU is a subset of reaped children CPU',
                             'worker maxrss overlaps sampled combined RSS; peaks differ in time',
                             'perf mmap pages overlap process RSS; fdinfo memory is not a complete allocator bound',
                             'entry-stage counters overlap and are not a partition of total events'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    report = analyze(args.log.read_text())
    with args.output.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps(dict(status=report['status'], sessions=len(report['sessions']), missing=report['missing'])))
    raise SystemExit(2)
