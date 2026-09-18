# SPDX-License-Identifier: GPL-2.0
"""Versioned bounded collector contract, checked before ARM acknowledgement.

This is a loading/interpretation contract, not a coverage or performance receipt.
Historical sessions without this contract remain readable by their old readers.
"""
from copy import deepcopy
import hashlib
from pathlib import Path

from periodic_plan import digest

SCHEMA = 'cis-collector-v1'
COMMON_MAPS = ['session_window', 'roots', 'events', 'stats']
COLLECTORS = {
    'ip': dict(profile=1, programs=['sample_ip'], maps=COMMON_MAPS,
               relation='sampled_execution', clock='sample_period', contexts=['task_or_interrupt_unknown'],
               object_kinds=[], source_filter='registered cgroup ancestors; executor is not async owner'),
    'owner': dict(profile=2, programs=['owner_state', 'owner_switch'],
                  maps=COMMON_MAPS + ['targets', 'stacks', 'watched', 'holders', 'holder_tasks', 'owner_attempts'],
                  relation='holder_waiter', clock='monotonic_wall_ns', contexts=['synchronous_task'],
                  object_kinds=['mutex', 'lockref'], source_filter='target wait opens bounded object watch; registered holder universe'),
    'sched': dict(profile=3, programs=['sched_wait'], maps=COMMON_MAPS + ['targets'],
                  relation='scheduler_wait', clock='monotonic_wall_ns', contexts=['event_task'],
                  object_kinds=[], source_filter='event task cgroup, not current'),
    'reclaim': dict(profile=4, programs=['reclaim_begin', 'reclaim_end', 'memcg_begin', 'memcg_end'],
                    maps=COMMON_MAPS + ['targets', 'stacks', 'pending'], relation='reclaim_interval',
                    clock='monotonic_wall_ns', contexts=['synchronous_task'], object_kinds=[],
                    source_filter='target begin, original identity retained to end'),
}


def contract(name):
    if name not in COLLECTORS:
        raise ValueError('unsupported collector')
    value = deepcopy(COLLECTORS[name])
    value.update(schema=SCHEMA, name=name, event_abi=1, bundle=name+'.bpf.o',
                 configuration='fixed OLK ARM64 non-RT; runtime capability check required',
                 limits=dict(window_ms=2000, targets=2, registered_roots=4,
                             entry_rate_per_s=200000, output_bytes=16 << 20,
                             memory_policy_bytes=64 << 20, total_memory_proven=False),
                 stop_protocol=['disable producers', 'quiesce callbacks', 'drain records',
                                'read terminal counters', 'destroy maps/programs', 'verify absent'],
                 audit=['entries', 'filter_rejections', 'lost', 'unknown_identity',
                        'unmatched', 'nested', 'window_truncation', 'object_reuse', 'capacity'],
                 unsupported='unreported counters are unknown, not zero; no automatic causal claim')
    return value


def bundle_manifest(bpf_path):
    return dict(schema='cis-collector-bundle-v1',
                objects={name+'.bpf.o': hashlib.sha256(object_path(bpf_path,name).read_bytes()).hexdigest()
                         for name in COLLECTORS},
                collectors={name: contract(name) for name in COLLECTORS})


def object_path(anchor, name):
    return Path(anchor).parent / contract(name)['bundle']


def validate_inventory(name, inventory):
    expected = contract(name)
    if not isinstance(inventory, dict) or inventory.get('schema') != 'cis-loaded-inventory-v1':
        raise ValueError('versioned loaded inventory required')
    if inventory.get('profile') != expected['profile']:
        raise ValueError('collector profile mismatch')
    for kind in ('maps', 'programs'):
        names, ids = inventory.get(kind[:-1] + '_names'), inventory.get(kind)
        if (not isinstance(names, list) or not all(isinstance(x, str) for x in names)
                or len(names) != len(set(names)) or set(names) != set(expected[kind])
                or not isinstance(ids, list) or len(ids) != len(names)
                or any(type(x) is not int or x <= 0 for x in ids) or len(ids) != len(set(ids))):
            raise ValueError('unexpected loaded ' + kind)
    cpus = inventory.get('ip_perf_cpus')
    if type(cpus) is not int or not 0 <= cpus <= 512 or (cpus > 0) != (name == 'ip'):
        raise ValueError('unexpected PMU collector activity')
    return digest(expected)
