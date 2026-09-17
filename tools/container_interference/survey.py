# SPDX-License-Identifier: GPL-2.0
"""Bounded, session-boundary snapshots and E0-only summaries."""
from collections import Counter
import json
import os
import re
import time

from periodic_plan import digest

COUNTERS = ('cpu.stat', 'cpu.pressure', 'memory.pressure', 'io.pressure', 'memory.events')
CONFIG = ('cpu.max', 'cpuset.cpus.effective', 'cpuset.mems.effective', 'memory.max', 'memory.high')
MAX_RAW = 16 * 1024 * 1024


def snapshot(root, clock=time.monotonic_ns):
    result = dict(id=root['id'], generation=root['generation'], files={}, config={}, errors={},
                  begin_ns=clock(), identity_valid=False)
    try:
        result['identity_valid'] = (os.fstat(root['fd']).st_ino == root['id'] and
                                   os.readlink('/proc/self/fd/%d' % root['fd']) == root['path'])
    except OSError as error:
        result['errors']['identity'] = error.errno
    if result['identity_valid']:
        for name in COUNTERS + CONFIG:
            start = clock()
            try:
                fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=root['fd'])
                try:
                    raw = os.read(fd, 4097)
                finally:
                    os.close(fd)
                if len(raw) > 4096:
                    raise ValueError('boundary file too large')
                value = raw.decode('ascii').strip()
                end = clock()
                if name in CONFIG:
                    result['config'][name] = value
                else:
                    counters = {}
                    for line in value.splitlines():
                        words = line.split()
                        if name.endswith('.pressure'):
                            for item in words[1:]:
                                if item.startswith('total='):
                                    counters[words[0] + '_total_usec'] = int(item[6:])
                        elif len(words) == 2:
                            counters[words[0]] = int(words[1])
                    if not counters:
                        raise ValueError('no counters')
                    result['files'][name] = dict(start_ns=start, end_ns=end, counters=counters)
            except (OSError, ValueError, UnicodeError) as error:
                result['errors'][name] = str(error)
    result['end_ns'] = clock()
    return result


def boundary_delta(before, after):
    if (not before.get('identity_valid') or not after.get('identity_valid') or
            (before['id'], before['generation']) != (after['id'], after['generation'])):
        return dict(status='IDENTITY_UNKNOWN', files={})
    if before['config'] != after['config']:
        return dict(status='CONFIG_CHANGED', files={})
    files, missing = {}, []
    for name in COUNTERS:
        a, b = before['files'].get(name), after['files'].get(name)
        if not a or not b or a['counters'].keys() != b['counters'].keys():
            missing.append(name)
            continue
        elapsed = b['start_ns'] - a['end_ns']
        changes = {key: b['counters'][key]-value for key, value in a['counters'].items()}
        if elapsed <= 0 or any(value < 0 for value in changes.values()):
            return dict(status='COUNTER_RESET_OR_BAD_TIME', files={})
        files[name] = dict(delta=changes, elapsed_ns=elapsed,
                           read_intervals_ns=[[a['start_ns'], a['end_ns']], [b['start_ns'], b['end_ns']]])
    return dict(status='PARTIAL' if missing else 'VALID', files=files, missing=missing,
                perf_window_aligned=False)


def read_ip(path, record):
    roots = record['root_identities']
    by_identity = {(root['id'], root['generation']): key for key, root in roots.items()}
    samples = {key: Counter() for key in roots}
    counts = Counter()
    units = {}
    fallback = False
    window = record.get('window', {})
    start, end = window.get('start_ns', 0), window.get('end_ns', 0)
    with open(path, 'rb') as stream:
        total = 0
        while True:
            raw = stream.readline(8193)
            if not raw:
                break
            total += len(raw)
            if total > MAX_RAW or len(raw) > 8192:
                raise ValueError('raw survey exceeds session bounds')
            event = json.loads(raw)
            if str(event.get('session_id')) != record['session_id']:
                raise ValueError('cross-session survey record')
            kind = event.get('kind')
            if kind == 'pmu_fallback':
                fallback = True
            if kind == 'ip_event':
                fields = dict(re.findall(r'(\w+)=([^\s]+)', event.get('detail', '')))
                units[int(fields['cpu'])] = fields['unit']
            if kind in ('buffer_loss', 'sample_schema_error', 'entry_budget_disable'):
                counts['quality_events'] += 1
            if kind != 'IP':
                continue
            fields = dict(re.findall(r'(\w+)=([^\s]+)', event.get('detail', '')))
            timestamp, weight = int(fields['sample_time_ns']), int(fields['weight'])
            if not start <= timestamp < end or weight < 0:
                counts['outside_window_or_bad_weight'] += 1
                continue
            key = by_identity.get((event.get('id'), event.get('generation')))
            if key is None:
                counts['unknown_identity'] += 1
                continue
            address = fields.get('ip', 'unknown')
            symbol = fields.get('symbol', 'unknown')
            cpu = int(fields['cpu'])
            samples[key][(cpu, address, symbol)] += weight
            if cpu not in units:
                counts['missing_pmu_unit'] += 1
            counts[key] += 1
    unique = set(units.values())
    unit = next(iter(unique)) if len(unique) == 1 else 'mixed_or_unknown_do_not_sum'
    if not units and fallback:
        unit = 'legacy_fallback_unit_unknown'
    return samples, counts, unit


def rate(delta, file, key):
    item = delta['files'].get(file)
    if not item or key not in item['delta']:
        return None
    return item['delta'][key] * 1e9 / item['elapsed_ns']


def summarize(record, path, previous, min_samples):
    samples, counts, unit = read_ip(path, record)
    receipt = record.get('receipt') or {}
    session_valid = (record.get('result') == 'COMPLETE' and record.get('objects_absent') is True
                     and not any(receipt.get(key, 0) for key in ('errors', 'dropped', 'output_error', 'stop_error'))
                     and not counts['quality_events'] and not counts['outside_window_or_bad_weight']
                     and not counts['missing_pmu_unit'] and unit != 'mixed_or_unknown_do_not_sum')
    report = dict(schema='cis-survey-v1', session_id=record['session_id'], unit=unit,
                  quality=dict(counts), evidence_level='E0', roots={},
                  boundary_scope='snapshots enclose prepare/cleanup gaps, not exact perf windows',
                  attribution='IP may include task/IRQ context; no object-holder or causal claim')
    for key, identity in record['root_identities'].items():
        before, after = record['boundary_before'][key], record['boundary_after'][key]
        delta = boundary_delta(before, after)
        epoch = digest(dict(identity=identity, config=before['config'], unit=unit,
                            declared_epoch=record.get('survey_epoch', 0),
                            source=record.get('source_identity', {})))
        config_known = set(before['config']) == set(CONFIG) and set(after['config']) == set(CONFIG)
        valid = session_valid and config_known and delta['status'] in ('VALID', 'PARTIAL') and counts[key] >= min_samples
        observed = dict(cpu_usec_per_s=rate(delta, 'cpu.stat', 'usage_usec'),
                        cpu_wait_usec_per_s=rate(delta, 'cpu.pressure', 'some_total_usec'),
                        memory_wait_usec_per_s=rate(delta, 'memory.pressure', 'some_total_usec'),
                        io_wait_usec_per_s=rate(delta, 'io.pressure', 'some_total_usec'))
        prior = previous.get(key)
        comparable = bool(valid and prior and prior.get('valid') and prior['epoch'] == epoch)
        reasons = []
        if comparable:
            for field, value in observed.items():
                reference = prior['rates'].get(field)
                if value is not None and reference is not None and value > max(reference*1.5, reference+10000):
                    reasons.append(field + '_increased_candidate_not_cause')
        report['roots'][key] = dict(valid=valid, epoch=epoch, rates=observed, counters=delta,
            status='INSUFFICIENT' if not valid else 'COMPARABLE' if comparable else 'REFERENCE',
            samples=counts[key], candidate=bool(reasons), reasons=reasons,
            metadata_coverage='image, credentials, mounts and workload phases require explicit epoch notification',
            top_ip=[dict(cpu=cpu, ip=ip, symbol=symbol, weight=weight) for (cpu, ip, symbol), weight
                    in (samples[key].most_common(8) if unit != 'mixed_or_unknown_do_not_sum'
                        else sorted(samples[key].items())[:8])])
    return report
