#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Derive admission from raw, version-bound evidence, never an all-PASS template.

Only implemented evidence readers can grant checks. Remaining readers fail
closed, even if an input document claims that their checks passed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

from periodic_plan import P1_CHECKS, digest
from session_check import analyze, extract

SOURCE_KEYS = ('controller_sha256', 'worker_sha256', 'residue_sha256',
               'bpf_sha256', 'support_sha256', 'kernel_release', 'kernel_notes_sha256', 'kernel_cmdline_sha256')

REQUIRED_EVIDENCE = {
    'identity_runtime': 'Controlled migration is a subclaim; registration races, short-lived descendants, generation reuse and non-target owners still require source-bound runtime evidence.',
    'lifecycle_runtime': 'Cancellation and five signal/recovery cases are subclaims; concurrent restart, failed publication and FAULTED admission barriers require a complete lifecycle reader.',
    'resource_failure_runtime': 'FD 4..24 and eight boundary cases are subclaims; allocator-internal loading/memory failures and rollback need additional raw evidence.',
    'storage_backpressure_runtime': 'Initial ENOSPC does not cover ARM, DRAIN, publication, blocked storage and bounded recovery; the full raw reader is not implemented.',
    'combined_cpu_enforcement_runtime': 'Live/reaped child accounting has tests; runtime budget-stop handoff and post-stop residual CPU need a complete evidence reader.',
    'kernel_background_cost': 'Business-context probe/PMU CPU and deferred kworker/RCU CPU ownership are not fully measured; process CPU alone cannot grant this check.',
    'total_memory_cost': 'Object metadata is partial; JIT/BTF/verifier transients, perf metadata, shared-page deduplication and deferred retention lack a complete upper bound.',
    'idle_throughput': 'One complete source-bound OFF/IDLE cost batch with both roles and five paired rounds is required.',
    'idle_p99': 'One complete source-bound OFF/IDLE open-loop latency batch with both roles and five paired rounds is required.',
    'ip_capture_quality': 'Functional capture alone is insufficient; a complete source-bound IP cost batch must include raw quality for all windows.',
    'owner_capture_quality': 'Functional capture alone is insufficient; a complete source-bound owner cost batch must include raw quality for all windows.',
    'owner_truth_runtime': 'Owner model/fixture results are not a full receipt; mutex and real lockref raw truth, private objects, switching, reuse, preemption and non-target owners must be cross-checked.',
    'ip_window_throughput': 'Both roles need a complete IP cost batch and accepted window capture quality; no historical binary substitution.',
    'owner_window_throughput': 'Both roles need a complete owner cost batch and accepted window capture quality; no historical binary substitution.',
    'window_latency_contract': 'A complete frozen v2 open-loop latency batch for IP and owner is required; OFF/OFF calibration is not observer performance evidence.',
}


def source_identity(value):
    if not isinstance(value, dict) or any(key not in value for key in SOURCE_KEYS):
        raise ValueError('complete source identity required')
    result = {key: value[key] for key in SOURCE_KEYS}
    if not isinstance(result['kernel_release'], str) or not result['kernel_release']:
        raise ValueError('kernel release missing')
    if any(not isinstance(result[key], str) or not re.fullmatch('[0-9a-f]{64}', result[key])
           for key in SOURCE_KEYS if key != 'kernel_release'):
        raise ValueError('invalid source hash')
    return result


def records(text):
    result = []
    for name, body in extract(text).items():
        if '/records/' in name and name.endswith('.json'):
            value, _ = json.JSONDecoder().raw_decode(body.lstrip())
            if not isinstance(value, dict) or 'session_id' not in value:
                raise ValueError('invalid session record')
            result.append(value)
    if len({r['session_id'] for r in result}) != len(result):
        raise ValueError('duplicate session IDs')
    return result


def combine(statuses):
    if not statuses:
        return 'BLOCKED'
    return 'FAIL' if 'FAIL' in statuses else 'PASS' if all(x == 'PASS' for x in statuses) else 'BLOCKED'


def evaluate(source, artifacts):
    source = source_identity(source)
    checks = {key: 'BLOCKED' for key in P1_CHECKS}
    details = {key: dict(reason=REQUIRED_EVIDENCE[key])
               for key in P1_CHECKS}
    index, rows = [], []
    if not artifacts:
        raise ValueError('raw evidence required')
    # A frozen batch is an indivisible input. Do not combine successful rounds
    # from several batches or upgrade historical binary identities.
    seen = set()
    for name, raw in artifacts:
        sha = hashlib.sha256(raw).hexdigest()
        if sha in seen:
            raise ValueError('duplicate evidence content')
        seen.add(sha)
        text = raw.decode('utf-8', errors='strict')
        found = records(text)
        if not found:
            raise ValueError('raw session evidence required; summary PASS is insufficient')
        for record in found:
            actual = record.get('source_identity') or record
            if source_identity(actual) != source:
                raise ValueError('source identity mismatch: ' + name)
        summary = analyze(text)
        entry = dict(name=name, sha256=sha, bytes=len(raw), sessions=len(found),
                     vm_exit_zero=summary['vm_exit_zero'])
        index.append(entry)
        rows.append((entry, summary))
        # Report what raw lifecycle evidence proves, but do not turn a bounded
        # subset into the broad P1 lifecycle/resource acceptance checks.
        from runtime_evidence import analyze as runtime_analyze
        runtime = runtime_analyze(text, source)
        from identity_evidence import analyze as identity_analyze
        identity = identity_analyze(extract(text), source)
        details['identity_runtime'].setdefault('controlled_migration_evidence', []).append(
            dict(artifact_sha256=sha, **identity))
        if identity['status'] == 'FAIL':
            checks['identity_runtime'] = 'FAIL'
        from kernel_resource_audit import analyze_session
        files = extract(text)
        for record in found:
            sid = str(record['session_id'])
            streams = [body for path,body in files.items() if path.endswith('/records/'+sid+'.jsonl')]
            audit = analyze_session(record, streams[0] if len(streams)==1 else '')
            details['total_memory_cost'].setdefault('object_inventory_evidence', []).append(
                dict(artifact_sha256=sha, **audit))
        for check in ('lifecycle_runtime', 'resource_failure_runtime'):
            details[check].setdefault('bounded_runtime_evidence', []).append(
                dict(artifact_sha256=sha, **runtime))
        # A subset cannot grant full acceptance, but a demonstrated failure
        # must remain a failure even when other required coverage is absent.
        for check, subchecks in {
                'lifecycle_runtime': ('cancellation', 'crash_recovery'),
                'resource_failure_runtime': ('boundary_failures', 'real_fd_exhaustion',
                                             'inventory_restoration')}.items():
            if any(runtime['subchecks'][key]['status'] == 'FAIL' for key in subchecks):
                checks[check] = 'FAIL'
    for mode in ('ip', 'owner'):
        candidates = [(entry, summary) for entry, summary in rows
                      if any(x['mode'] == mode and x['interval']['n'] == 5 for x in summary['cost'])]
        if len(candidates) != 1:
            details[mode + '_capture_quality'] = dict(reason='exactly one frozen complete cost batch required',
                                                       batches=len(candidates))
            continue
        entry, summary = candidates[0]
        costs = [row for row in summary['cost'] if row['mode'] == mode]
        quality = [row['capture_quality']['status'] for row in costs if row['capture_quality']]
        if not entry['vm_exit_zero']:
            quality.append('FAIL')
        check = mode + '_capture_quality'
        checks[check] = combine(quality) if len(costs) == 4 else 'BLOCKED'
        details[check] = dict(artifact_sha256=entry['sha256'], windows=[row['capture_quality'] for row in costs])
        check = mode + '_window_throughput'
        checks[check] = combine([row['status'] for row in costs if row['workload'] == 'throughput'] +
                               [checks[mode + '_capture_quality']])
        details[check] = dict(artifact_sha256=entry['sha256'], results=[row for row in costs if row['workload'] == 'throughput'])
    idle_batches = [(entry, summary) for entry, summary in rows
                    if any(x['mode'] == 'idle' for x in summary['cost']) and
                    all(x['interval']['n'] == 5 for x in summary['cost'] if x['mode'] == 'idle')]
    if len(idle_batches) == 1:
        entry, summary = idle_batches[0]
        for workload, check in (('throughput', 'idle_throughput'), ('latency', 'idle_p99')):
            costs = [x for x in summary['cost'] if x['mode'] == 'idle' and x['workload'] == workload]
            checks[check] = combine([x['status'] for x in costs]) if len(costs) == 2 and entry['vm_exit_zero'] else 'BLOCKED'
            details[check] = dict(artifact_sha256=entry['sha256'], results=costs)
    tail_batches=[(entry,summary) for entry,summary in rows
                  if summary.get('cost_protocol',{}).get('version')==2]
    if len(tail_batches)==1:
        entry,summary=tail_batches[0]
        results=[row for row in summary['cost'] if row['workload']=='latency' and row['mode'] in ('ip','owner')]
        checks['window_latency_contract']=combine([x['status'] for x in results]) if len(results)==4 and entry['vm_exit_zero'] else 'BLOCKED'
        details['window_latency_contract']=dict(artifact_sha256=entry['sha256'],
             protocol=summary['cost_protocol'],results=results,
             scope='frozen engineering tail target, not a production service SLO')
    # Bounded identity/object observations do not complete the larger runtime
    # contracts; process RSS and enumerated objects do not prove all resources.
    result = dict(schema='cis-p1-admission-v2', source=source, checks=checks,
                  phase_complete=all(x == 'PASS' for x in checks.values()),
                  evidence_index_sha256=digest(index), evidence_index=index, details=details,
                  generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--log', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    value = evaluate(json.loads(args.manifest.read_text()), [(str(p), p.read_bytes()) for p in args.log])
    with args.output.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
    print(json.dumps(dict(phase_complete=value['phase_complete'], checks=value['checks']), indent=2))
    raise SystemExit(0 if value['phase_complete'] else 2)
