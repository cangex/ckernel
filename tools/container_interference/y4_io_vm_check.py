#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Replay private-file pressure evidence independently of the guest verdict."""
import argparse
import hashlib
import json
from pathlib import Path

from block_report import analyze
from collector_manifest import contract
from prototype_admission import SOURCE_KEYS
from session_check import extract
from source_switches import validate
from y4_io_check import CASES, case_order, check_case


def verify(serial, output):
    if serial.stat().st_size > 128 << 20:
        raise ValueError('serial capacity')
    raw = serial.read_bytes(); text = raw.decode(); files = extract(text)
    prefix = '/tmp/y4-io-evidence/'
    def value(name):
        return json.JSONDecoder().raw_decode(files[prefix + name].lstrip())[0]
    output.mkdir(mode=0o700); errors = []; states = []
    plan, declared, permit = [value(k + '.json') for k in ('plan', 'result', 'permit')]
    layout = value('filesystem-layout.json')
    if (len(layout) != 2 or len({r['uuid'] for r in layout}) != 2 or
            any(r.get('serial') != 'cis-y3-fs%d' % i or r.get('mount') != '/fs%d' % i or
                r.get('orphan_file') is not bool(i) for i, r in enumerate(layout))):
        errors.append('scratch_filesystem_identity')
    if ('CIS_PROFILE_VM_EXIT=0' not in text.splitlines() or
            'CIS_FILESYSTEM_UNLOAD=0' not in text.splitlines()):
        errors.append('guest_exit_or_unload')
    if any(s in text for s in ('BUG: KASAN:', 'Oops:', 'Kernel panic', 'WARNING: CPU:')):
        errors.append('kernel_warning')
    if (plan.get('schema') != 'cis-y4-io-plan-v1' or plan.get('order') != case_order() or
            plan.get('cases') != CASES or plan.get('window_ms') != 2000 or
            plan.get('bytes_per_actor') != 8388608 or plan.get('private_directories') is not True or
            plan.get('cpus') != [0, 1] or plan.get('manager_cpu') != 7 or
            plan.get('guest_settings') != dict(dirty_background_bytes=1048576, dirty_bytes=4194304)):
        errors.append('frozen_plan')
    if [s['label'] for s in declared['states']] != [s['label'] for s in case_order()]:
        errors.append('state_order')
    if any(declared['source'].get(k) != permit['source'].get(k) or
           plan['source'].get(k) != permit['source'].get(k) for k in SOURCE_KEYS):
        errors.append('source_binding')
    for expected in case_order():
        label = expected['label']; ev = value(label + '-evidence.json')
        if any(ev.get(k) != v for k, v in expected.items()):
            errors.append('state_plan_' + label)
        logs = [files[prefix + label + '-%d.log' % i] for i in range(2)]
        report = None; identities = None; costs = {}; coverage = {}
        if ev['enabled']:
            sid = str(ev['session_id'])
            if not sid.isascii() or not sid.isdigit():
                raise ValueError('session id')
            record = value('records/' + sid + '.json')
            if any(record.get(k) != permit['source'].get(k) for k in SOURCE_KEYS):
                errors.append('session_source_' + label)
            capture = (files[prefix + 'records/' + sid + '.jsonl'].rstrip() + '\n').encode()
            report = analyze(record, capture)
            identities = [record['root_identities'][t] for t in ev['targets']]
            if (record['nonce'] != label or record['window'] != ev['window'] or
                    not record['objects_absent'] or record.get('collector') != 'block'):
                errors.append('session_boundary_' + label)
            validate(ev['active_sources'], 'block', record['requested_ns'], record['window']['end_ns'])
            audit = record['receipt'].get('program_audit', {})
            if (audit.get('required') is not True or audit.get('valid') is not True or
                    audit.get('programs') != len(contract('block')['programs']) or
                    audit.get('recursion_misses') != 0):
                errors.append('program_audit_' + label)
            pressure = report['pressure']
            coverage = dict(requests=len(report['requests']), tag_snapshots=len(pressure['tag_snapshots']),
                dirty_pauses=len(pressure['dirty_pauses']),
                positive_pauses=sum(p['positive_pause_requested'] for p in pressure['dirty_pauses']),
                wait_pool_associations=len(pressure['wait_pool_associations']))
            costs = dict(process_capturing_cpu_ns=record['process_cpu_budget']['phase_peak_cpu_ns']['CAPTURING'],
                         combined_process_rss_peak_bytes=record['combined_rss_peak_bytes'])
            (output / (label + '-report.json')).write_text(json.dumps(report, indent=2))
            (output / (label + '-record.json')).write_text(json.dumps(record, indent=2))
            (output / (label + '.jsonl')).write_bytes(capture)
        else:
            validate(ev['active_sources'], None, 0, 2**64 - 1)
            if ev['session_id'] is not None:
                errors.append('off_session_' + label)
        validate(ev['idle_sources'], None, ev['window']['start_ns'], 2**64 - 1)
        checked = check_case(ev['case'], ev['window'], logs, report, identities)
        if checked['status'] != 'PASS' or ev['exit_codes'] != [0, 0]:
            errors.append(label)
        for edge in ('before', 'after'):
            for root in ev[edge]['roots']:
                values = dict(line.split() for line in root['memory.events'].splitlines())
                if any(int(values.get(k, 0)) for k in ('oom', 'oom_kill', 'max')):
                    errors.append('resource_error_' + label)
        states.append(dict(**expected, result=checked, coverage=coverage, costs=costs))
    result = dict(status='FAIL' if errors else 'PASS_SCOPED', errors=errors, states=states,
        source=declared['source'], serial_sha256=hashlib.sha256(raw).hexdigest(),
        scope='private-file request tag snapshots and native dirty pauses; shared/separate devices',
        performance_certification='NOT_ACCEPTED', causal_blocking_tenant='NOT_IDENTIFIED',
        tag_pool_wait_runtime='OBSERVED' if any(s['coverage'].get('wait_pool_associations') for s in states) else 'NOT_OBSERVED',
        limits=['tag points are not complete slot lifetimes or pool occupancy',
                'functional scratch-device pressure is not a physical-disk performance result'])
    (output / 'verification.json').write_text(json.dumps(result, indent=2))
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('serial', type=Path); p.add_argument('output', type=Path)
    args = p.parse_args(); r = verify(args.serial, args.output)
    print(json.dumps(dict(status=r['status'], errors=r['errors'], states=len(r['states']))))
    raise SystemExit(r['status'] != 'PASS_SCOPED')
