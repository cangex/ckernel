# SPDX-License-Identifier: GPL-2.0
"""Explicit incomplete gates, independent of old resident-mode acceptance."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import statistics

REQUIRED = ('p1_admission', 'scheduler_model', 'identity_runtime', 'periodic_runtime',
            'fairness_runtime', 'fault_runtime', 'idle_throughput', 'idle_p99',
            'cycle_throughput', 'cycle_p99', 'window_throughput', 'window_latency_slo',
            'total_cpu', 'total_memory', 'coverage')


def completion(results, evidence_root=None):
    checks, provenance = {}, {}
    root = Path(evidence_root).resolve() if evidence_root is not None else None
    for key in REQUIRED:
        entry = results.get(key, 'BLOCKED')
        status = entry.get('status', 'BLOCKED') if isinstance(entry, dict) else entry
        if status == 'PASS':
            artifacts = entry.get('artifacts', []) if isinstance(entry, dict) else []
            valid = bool(root and artifacts)
            for item in artifacts:
                try:
                    path = (root/item['path']).resolve()
                    if not path.is_relative_to(root) or not path.is_file():
                        valid = False
                        break
                    sha = hashlib.sha256()
                    with path.open('rb') as stream:
                        for chunk in iter(lambda: stream.read(65536), b''): sha.update(chunk)
                    if sha.hexdigest() != item['sha256']:
                        valid = False
                except (OSError, ValueError, KeyError, TypeError):
                    valid = False
            if not valid:
                status = 'BLOCKED'
                provenance[key] = 'PASS lacks verified evidence references'
        checks[key] = status
    if any(value not in ('PASS', 'FAIL', 'BLOCKED', 'UNSUPPORTED', 'SKIP') for value in checks.values()):
        raise ValueError('invalid acceptance status')
    return dict(schema='cis-p2-completion-v1', checks=checks,
                phase_complete=all(value == 'PASS' for value in checks.values()),
                unpassed=[key for key, value in checks.items() if value != 'PASS'],
                provenance_errors=provenance,
                scope='audited gate aggregation with file integrity; not a substitute for individual runtime validators')


def paired_cost(pairs, metric, threshold_pct):
    """Frozen n=5 paired t interval; no dropping or extending unfavorable runs."""
    if metric not in ('throughput', 'p99') or len(pairs) != 5:
        return dict(status='BLOCKED', reason='requires frozen n=5 and a supported metric')
    values = []
    for pair in pairs:
        off, on = pair.get('off'), pair.get('on')
        if (isinstance(off, bool) or isinstance(on, bool) or not isinstance(off, (int, float))
                or not isinstance(on, (int, float)) or off <= 0 or on <= 0):
            return dict(status='BLOCKED', reason='invalid pair, none discarded')
        value = (1-on/off)*100 if metric == 'throughput' else (on/off-1)*100
        if not math.isfinite(value):
            return dict(status='BLOCKED', reason='non-finite pair')
        values.append(value)
    mean = statistics.mean(values)
    half = 2.776445105 * statistics.stdev(values) / 5**.5
    low, high = mean-half, mean+half
    return dict(status='PASS' if high <= threshold_pct else 'FAIL' if low > threshold_pct else 'BLOCKED',
                n=5, mean_pct=mean, lower95_pct=low, upper95_pct=high,
                threshold_pct=threshold_pct, pairs_pct=values)


def cycle_cost(process_cpu_ns, background_cpu_ns, wall_ns):
    if wall_ns <= 0 or process_cpu_ns < 0 or (background_cpu_ns is not None and background_cpu_ns < 0):
        raise ValueError('invalid CPU measurement')
    return dict(process_cpu_one_cpu_pct=100*process_cpu_ns/wall_ns,
                total_cpu_one_cpu_pct=None if background_cpu_ns is None else
                100*(process_cpu_ns+background_cpu_ns)/wall_ns,
                complete=background_cpu_ns is not None,
                business_overhead_inferred=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('checks')
    parser.add_argument('--evidence-root')
    args = parser.parse_args()
    print(json.dumps(completion(json.loads(Path(args.checks).read_text()), args.evidence_root), indent=2))
