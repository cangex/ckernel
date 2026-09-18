# SPDX-License-Identifier: GPL-2.0
"""Join enumeration to per-object metadata without pretending it is allocation accounting."""
import json
import re


def analyze_session(record, stream):
    expected = record.get('inventory') or {}
    sid = str(record['session_id'])
    objects, defects, unknown = {}, [], []
    for line in stream.splitlines():
        if not line.startswith('{'):
            continue
        event = json.loads(line)
        if str(event.get('session_id')) != sid:
            raise ValueError('object inventory crosses session boundary')
        if event.get('kind') != 'kernel_object_inventory':
            continue
        fields = dict(re.findall(r'(\w+)=([^ ;]+)', event.get('detail','')))
        kind = fields.get('object_type')
        if kind not in ('map', 'program'):
            raise ValueError('unknown object type')
        numeric = {k:int(v) for k,v in fields.items() if k != 'object_type'}
        needed = {'object_id','info_valid','fdinfo_valid','fdinfo_bytes','allocation_upper_bound_known'}
        needed |= {'map_type','key_bytes','value_bytes','max_entries','map_flags'} if kind=='map' else {'jit_code_bytes','xlated_bytes','btf_id','nr_map_ids'}
        if set(numeric) != needed or any(v < 0 for v in numeric.values()):
            raise ValueError('incomplete object metadata')
        key = (kind,numeric['object_id'])
        if key in objects:
            raise ValueError('duplicate object inventory within session')
        if numeric['info_valid'] != 1 or not numeric['object_id']:
            unknown.append('failed '+kind+' info lookup')
        elif numeric['object_id'] not in expected.get(kind+'s',[]):
            defects.append('object absent from ownership journal: '+str(key))
        if numeric['fdinfo_valid'] != 1:
            unknown.append('missing fdinfo: '+str(key))
        if numeric['allocation_upper_bound_known'] != 0:
            raise ValueError('object information cannot claim allocation upper bound')
        objects[key] = dict(object_type=kind, **numeric)
    for kind in ('map','program'):
        ids = expected.get(kind+'s')
        if not isinstance(ids,list) or len(ids)!=len(set(ids)):
            unknown.append('missing/invalid '+kind+' ownership list'); continue
        for ident in ids:
            if (kind,ident) not in objects:
                unknown.append('missing inventory: '+str((kind,ident)))
    if not objects:
        unknown.append('no raw object inventory')
    return dict(schema='cis-kernel-resource-audit-v1', session_id=sid,
                inventory_status='FAIL' if defects else 'BLOCKED' if unknown else 'PASS',
                defects=defects, inventory_unknown=unknown, objects=list(objects.values()),
                jit_code_bytes=sum(x.get('jit_code_bytes',0) for x in objects.values()),
                total_upper_bound_bytes=None, total_memory_complete=False, background_cpu_complete=False,
                enumerable_objects_absent=record.get('objects_absent') is True,
                reclaim_completed=None,
                missing=['JIT allocator page rounding and metadata; BTF/verifier transient allocations',
                         'perf allocation metadata and static monitoring structures',
                         'deduplicated user/kernel page attribution',
                         'in-business observer CPU and deferred work completion/CPU'],
                limits='JIT code bytes are payload, not resident allocation; IDs disappearing are not deferred reclamation proof')
