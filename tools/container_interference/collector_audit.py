# SPDX-License-Identifier: GPL-2.0
"""Read bounded raw collector scope counters without inventing zero coverage."""
import json
import re

from collector_manifest import validate_inventory


def audit(record, raw):
    if len(raw) > 16 << 20: raise ValueError('session audit input limit')
    contract = None
    errors = []
    try: contract = validate_inventory(record['collector'], record.get('inventory'))
    except (ValueError, KeyError) as error: errors.append(str(error))
    names = {'terminal_counters': ('received', 'emitted', 'rejected'),
             'terminal_coverage': ('lost', 'owner_skipped'),
             'terminal_scope': ('unknown', 'overdepth', 'unmatched', 'nested', 'expired', 'irq_context'),
             'owner_entry_stages': ('owner_entries', 'sched_entries', 'target_waits', 'watch_events')}
    found = {}
    optional = {'owner_map_updates': ('watch_races', 'watch_failed', 'holder_failed', 'attempt_failed')}
    for line in raw.splitlines():
        if len(line) > 8192: raise ValueError('audit record length')
        row = json.loads(line)
        if not isinstance(row, dict): raise ValueError('audit record must be an object')
        if str(row.get('session_id')) != str(record['session_id']): raise ValueError('audit session mismatch')
        kind = row.get('kind')
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
    return dict(schema='cis-collector-audit-v1', status='FAIL' if errors else 'BLOCKED' if missing else 'PASS',
                collector_contract_sha256=contract, errors=errors, missing=missing, counters=found,
                counters_overlap=True, population_coverage=None, object_reuse_coverage=None,
                note='scope audit only, not a zero-loss, attribution or performance acceptance')
