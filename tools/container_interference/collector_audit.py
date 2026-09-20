# SPDX-License-Identifier: GPL-2.0
"""Read bounded raw collector scope counters without inventing zero coverage."""
import json
import re

from collector_manifest import validate_record_inventory, contract as current_contract
from periodic_plan import digest


def audit(record, raw):
    if len(raw) > 16 << 20: raise ValueError('session audit input limit')
    contract = None
    errors = []
    try: contract = validate_record_inventory(record)
    except (ValueError, KeyError) as error: errors.append(str(error))
    names = {'terminal_counters': ('received', 'emitted', 'rejected'),
             'terminal_coverage': ('lost', 'owner_skipped'),
             'terminal_scope': ('unknown', 'overdepth', 'unmatched', 'nested', 'expired', 'irq_context'),
             'owner_entry_stages': ('owner_entries', 'sched_entries', 'target_waits', 'watch_events')}
    found = {}
    owner_resources=set()
    selections=[]; closes=[]
    optional = {'owner_map_updates': ('watch_races', 'watch_failed', 'holder_failed', 'attempt_failed')}
    for line in raw.splitlines():
        if len(line) > 8192: raise ValueError('audit record length')
        row = json.loads(line)
        if not isinstance(row, dict): raise ValueError('audit record must be an object')
        if str(row.get('session_id')) != str(record['session_id']): raise ValueError('audit session mismatch')
        kind = row.get('kind')
        if kind=='backend_source_filter': selections.append(row.get('detail',''))
        if kind=='backend_source_filter_closed': closes.append(row.get('detail',''))
        if record.get('collector')=='alloc_backend' and kind=='MAPLE_ALLOC':
            errors.append('backend-only capture contains excluded Maple context')
        if kind=='OWNER':
            resource=re.search(r'(?:^|\s)resource=(\d+)(?:\s|$)',row.get('detail',''))
            if resource: owner_resources.add(int(resource[1]))
            else: errors.append('owner record missing resource')
        if kind not in names and kind not in optional: continue
        if kind in found: raise ValueError('duplicate terminal counter group')
        detail = row.get('detail', '')
        if not isinstance(detail, str): raise ValueError('audit detail must be text')
        fields = dict(re.findall(r'(\w+)=(\d+)(?:\s|$)', detail))
        found[kind] = {name: int(fields[name]) if name in fields else None
                       for name in names.get(kind,optional.get(kind))}
    missing = [kind for kind in names if kind not in found]
    for kind, fields in names.items():
        found.setdefault(kind, {name: None for name in fields})
        missing.extend(kind+'.'+name for name, value in found[kind].items() if value is None)
    if record.get('collector')=='fd' and owner_resources-{3}:
        errors.append('FD source emitted another resource kind')
    if record.get('collector')=='slub' and owner_resources-{4}:
        errors.append('SLUB source emitted another resource kind')
    if (record.get('collector')=='owner' and contract and
            record.get('collector_contract_sha256')==contract and owner_resources-{1,2}):
        errors.append('owner source emitted another resource kind')
    backend=None
    if record.get('collector') in ('allocator','alloc_backend','slub','page_backend') and (
            selections or record.get('backend_selection') is not None or
            record.get('collector_contract_sha256')==digest(current_contract(record['collector']))):
        try:
            if len(selections)!=1: raise ValueError('backend selection count')
            backend=dict(p.split('=',1) for p in selections[0].split())
            requested=record.get('backend_selection')
            if backend==dict(protocol='1',lease='0',legacy_boot_selection='1'):
                if requested or closes or record['collector']=='page_backend': raise ValueError('explicit selection without native lease')
            else:
                if (set(backend)!={'protocol','lease','readback','cache','nodes','node_scope','allocation_release_scope'} or
                        backend['protocol']!='1' or backend['lease']!='1' or backend['readback']!='1' or
                        backend['node_scope']!=('page_zone' if record['collector']=='page_backend' else 'slub_lock_only') or
                        backend['allocation_release_scope']!=('not_tracked' if record['collector']=='page_backend' else 'whole_selected_cache') or
                        not re.fullmatch(r'[A-Za-z0-9_-]{1,63}',backend['cache']) or
                        closes!=['lease=0 close_after_detach=1']):
                    raise ValueError('backend lease lifecycle')
                nodes=[] if backend['nodes']=='*' else [int(v) for v in backend['nodes'].split(',')]
                if (len(nodes)>8 or len(set(nodes))!=len(nodes) or any(not 0<=n<1024 for n in nodes) or
                        nodes and record['collector'] not in ('slub','page_backend') or
                        record['collector']=='page_backend' and backend['cache']!='page_zone'):
                    raise ValueError('backend node selection')
                if requested and requested!=dict(cache=backend['cache'],nodes=nodes):
                    raise ValueError('backend selection readback mismatch')
        except (ValueError,KeyError): errors.append('backend_selection_invalid')
    return dict(schema='cis-collector-audit-v1', status='FAIL' if errors else 'BLOCKED' if missing else 'PASS',
                collector_contract_sha256=contract, errors=errors, missing=missing, counters=found,
                counters_overlap=True, owner_resources=sorted(owner_resources),
                backend_selection=backend,
                population_coverage=None, object_reuse_coverage=None,
                note='scope audit only, not a zero-loss, attribution or performance acceptance')
