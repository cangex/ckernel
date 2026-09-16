#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Fail-closed acceptance inventory. IMPLEMENTED never satisfies a runtime gate."""
import argparse
import hashlib
import json
import math
import pathlib

STATES = {'IMPLEMENTED', 'PASS', 'FAIL', 'SKIP', 'UNSUPPORTED', 'BLOCKED'}
REQUIRED = {
    'S0': ['baseline_tree', 'image_modules_build', 'isolated_boot', 'container_baseline'],
    'S1': ['identity', 'migration_samples', 'churn_cleanup', 'registration_races'],
    'S2': ['ambient_throughput', 'ambient_p99', 'memory_budget', 'configuration_epoch'],
    'S3': ['state_machine', 'expiry_cleanup', 'trigger_storm', 'entry_budget', 'pairing'],
    'S4': ['mutex_truth', 'private_objects', 'phase_change', 'cpu_quota', 'cpu_competition', 'reclaim', 'address_reuse'],
    'S5': ['async_lineage', 'async_cancel_requeue', 'spe'],
    'S6': ['active_1_12_24_48', 'idle_128_256', 'paired_n5', 'ambient_throughput', 'ambient_p99', 'diagnostic_throughput', 'background_cpu_memory'],
}


def performance_gate(stage, name, reports):
    """Recompute numerical gates; a hashed arbitrary log is not a measurement."""
    workload = 'open-loop' if name == 'ambient_p99' else 'bench'
    mode = 'diag' if name == 'diagnostic_throughput' else 'ip'
    threshold = 2 if workload == 'open-loop' else 3 if mode == 'diag' else 1
    for report in reports:
        if not isinstance(report, dict) or not report.get('coverage_valid'):
            continue
        if report.get('failures') or report.get('observer_errors') or report.get('missing_coverage'):
            continue
        rows = [row for row in report.get('results', [])
                if row.get('workload') == workload and row.get('mode') == mode]
        required = {(None, role) for role in ('target', 'bystander')}
        if stage == 'S6':
            required = {(count, role) for count in (1, 12, 24, 48)
                        for role in ('target', 'bystander') if count > 1 or role == 'target'}
        valid = set()
        for row in rows:
            interval = row.get('95pct_interval', [])
            if (row.get('n', 0) < 5 or len(interval) != 2 or
                    not all(isinstance(v, (int, float)) and math.isfinite(v) for v in interval) or
                    interval[0] > interval[1] or interval[1] > threshold or
                    row.get('threshold_percent') != threshold):
                continue
            valid.add((row.get('containers') if stage == 'S6' else None, row.get('role')))
        if required <= valid:
            return True
    return False


def check(manifest, directory):
    stages, errors = {}, []
    for stage, required in REQUIRED.items():
        items = manifest.get('stages', {}).get(stage, {})
        results = {}
        for name in required:
            item = items.get(name, {'status': 'BLOCKED', 'reason': 'result absent'})
            status = item.get('status')
            if status not in STATES:
                errors.append(f'{stage}/{name}: invalid status')
                status = 'FAIL'
            verified = 0
            reports = []
            for evidence in item.get('evidence', []):
                path = (directory / evidence['path']).resolve()
                if not path.is_relative_to(directory.resolve()) or not path.is_file():
                    errors.append(f'{stage}/{name}: missing/outside artifact')
                    continue
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                if digest != evidence.get('sha256'):
                    errors.append(f'{stage}/{name}: hash mismatch')
                else:
                    verified += 1
                    if path.suffix == '.json':
                        try:
                            reports.append(json.loads(path.read_text()))
                        except (ValueError, UnicodeError):
                            errors.append(f'{stage}/{name}: invalid JSON artifact')
            acceptable = status == 'PASS' or (stage == 'S5' and name == 'spe' and status == 'UNSUPPORTED')
            if acceptable and not verified:
                errors.append(f'{stage}/{name}: passing claim lacks verified artifact')
                acceptable = False
            if acceptable and name in ('ambient_throughput', 'ambient_p99', 'diagnostic_throughput'):
                if not performance_gate(stage, name, reports):
                    errors.append(f'{stage}/{name}: numerical or coverage gate not met')
                    acceptable = False
            results[name] = {'status': status, 'accepted': acceptable, 'reason': item.get('reason', '')}
        stages[stage] = {'items': results, 'accepted': all(i['accepted'] for i in results.values())}
    return {'stages': stages, 'errors': errors, 'complete': not errors and all(s['accepted'] for s in stages.values()),
            'scope': manifest.get('scope', 'UNSPECIFIED'),
            'rule': 'No SKIP or IMPLEMENTED may satisfy core acceptance; only optional SPE may be unsupported.'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('manifest', type=pathlib.Path)
    parser.add_argument('output', type=pathlib.Path)
    args = parser.parse_args()
    result = check(json.loads(args.manifest.read_text()), args.manifest.parent)
    with args.output.open('x') as output:
        json.dump(result, output, indent=2)
        output.write('\n')
    print(json.dumps({k: v['accepted'] for k, v in result['stages'].items()}))
    return 0 if result['complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
