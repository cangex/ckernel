# SPDX-License-Identifier: GPL-2.0
"""Periodic admission contract. Capacity is not a detection guarantee."""
import hashlib
import json
import math
import re

NS = 1_000_000_000
MAX_ROOTS = 256
P1_CHECKS = (
    'identity_runtime', 'lifecycle_runtime', 'resource_failure_runtime',
    'storage_backpressure_runtime', 'combined_cpu_enforcement_runtime',
    'kernel_background_cost', 'total_memory_cost', 'idle_throughput', 'idle_p99',
)
DEFAULTS = dict(interval_s=60, window_ms=2000, targets_per_session=2,
                jitter_ms=1000, seed=1, min_samples=32,
                max_sample_age_s=0, process_cpu_ms=600,
                prepare_cpu_ms=250, drain_cpu_ms=250,
                rss_bytes=64 * 1024 * 1024, disk_bytes=256 * 1024 * 1024,
                retain_seconds=3600, retain_sessions=64)


def validate_plan(value):
    if not isinstance(value, dict) or set(value) - set(DEFAULTS):
        raise ValueError('unknown periodic plan field')
    result = dict(DEFAULTS, **value)
    limits = dict(interval_s=(60, 86400), window_ms=(100, 2000),
                  targets_per_session=(1, 2), jitter_ms=(0, 5000), seed=(0, 2**32-1),
                  min_samples=(1, 10000), max_sample_age_s=(0, 31*86400),
                  process_cpu_ms=(50, 2000), prepare_cpu_ms=(10, 1000),
                  drain_cpu_ms=(10, 1000), rss_bytes=(16*2**20, 64*2**20),
                  disk_bytes=(32*2**20, 1024*2**20), retain_seconds=(60, 31*86400),
                  retain_sessions=(1, 128))
    for key, (low, high) in limits.items():
        if type(result[key]) is not int or not low <= result[key] <= high:
            raise ValueError('invalid periodic plan: ' + key)
    if result['process_cpu_ms'] < max(result['prepare_cpu_ms'], result['drain_cpu_ms']):
        raise ValueError('whole-session CPU budget smaller than a stage budget')
    return result


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def capacity(plan, count):
    if type(count) is not int or not 0 <= count <= MAX_ROOTS:
        raise ValueError('registration capacity')
    ideal = math.ceil(count / plan['targets_per_session']) * plan['interval_s']
    # One slot is always reserved for the least-recently-served root. Candidate
    # revisits may consume the other slot; failures/manual work add unbounded delay.
    fair = count * (plan['interval_s'] + plan['jitter_ms']/1000)
    requested = plan['max_sample_age_s']
    return dict(roots=count, ideal_round_s=ideal, fair_service_bound_s=fair,
                requested_sample_age_s=requested,
                capacity_admissible=not requested or fair <= requested,
                sample_age_guaranteed=False,
                conditions='stable roots, all slots available and successful; valid samples not guaranteed')


def require_acceptance(evidence, manifest):
    if not isinstance(evidence, dict) or evidence.get('schema') != 'cis-p1-admission-v1':
        raise ValueError('P1 acceptance receipt required')
    if evidence.get('phase_complete') is not True:
        raise ValueError('P1 has not passed')
    expected = {key: manifest[key] for key in
                ('controller_sha256', 'worker_sha256', 'bpf_sha256', 'support_sha256',
                 'kernel_release', 'kernel_notes_sha256')}
    if evidence.get('source') != expected:
        raise ValueError('P1 receipt does not match current binaries/modules/kernel')
    if not isinstance(evidence.get('checks'), dict):
        raise ValueError('P1 checks missing')
    missing = [key for key in P1_CHECKS if evidence['checks'].get(key) != 'PASS']
    if missing:
        raise ValueError('P1 checks not passed: ' + ', '.join(missing))
    if not isinstance(evidence.get('evidence_index_sha256'), str) or not re.fullmatch('[0-9a-f]{64}', evidence['evidence_index_sha256']):
        raise ValueError('raw evidence index digest required')
    return digest(evidence)
