#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""X1 first layer: source-bound contention intervals, never inferred owners."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from collector_audit import audit
from explain import explain


def analyze(record, raw):
    if record.get('collector') != 'sync': raise ValueError('sync capture required')
    base = explain(record, raw)
    scope = audit(record, raw)
    candidates = []; excluded=Counter()
    for finding in base['findings']:
        if finding.get('observation') != 'lock_contention_interval': continue
        fields = finding['fields']; flags = int(fields.get('flags', '0'), 0)
        if flags & (8 | 16) or flags & ~0x8000003f:
            excluded['unsupported_flags']+=1
            continue
        classes=flags&(2|4|32)
        if classes not in (0,2,4,32):
            excluded['ambiguous_access_flags']+=1
            continue
        # Mutex/rwsem may include an optimistic-spin phase; SPIN is not its type.
        access = 'mutex' if classes==32 else 'read' if classes==2 else 'write' if classes==4 else 'spin' if flags&1 else 'unknown'
        obj = fields.get('object')
        if not obj or int(obj, 0) == 0:
            excluded['missing_object']+=1
            continue
        candidates.append(dict(evidence='E1', container_id=finding['id'], generation=finding['generation'],
            task_id=int(fields['tid'], 0), address=obj, object_lifetime='UNKNOWN',
            access_class=access, raw_flags=flags, interval_ns=finding['interval_ns'], metric='wall_ns',
            spin_phase_flag=bool(flags&1),
            outcome='aborted_or_failed' if flags & 0x80000000 else 'contention_end_observed',
            stack_leaf_to_root=finding['stack_leaf_to_root'], holder=None,
            relation='wait_interval_only', other_container_identified=False))
    return dict(schema='cis-sync-candidates-v1', quality=base['quality'], scope_audit=scope,
                analysis_source_sha256=dict(base['analysis_source_sha256'], **{
                    name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                    for name in ('sync_report.py','collector_audit.py','collector_manifest.py','periodic_plan.py')}),
                candidates=candidates, omitted_findings=base['omitted_findings'], excluded=dict(excluded),
                unknown=base['unknown'], source=base['source'], raw_sha256=base['raw_sha256'],
                coverage=dict(discovery='IMPLEMENTED', owner='NOT_IMPLEMENTED', lifetime='UNRESOLVED',
                              source_recursion_completeness='UNVERIFIED', causal='NOT_CLAIMED'),
                limits=['qspinlock pending-bit path is not covered by the observed MCS tracepoint pair',
                        'rwsem read/write flags do not reveal its writer or reader set',
                        'elapsed wall time includes interruptions; it is not pure spin cycles',
                        'do not group recycled addresses into a holder or blame relation',
                        'runtime validation is separate from schema and synthetic unit tests'])


if __name__ == '__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('record'); parser.add_argument('raw'); parser.add_argument('output')
    args=parser.parse_args()
    if Path(args.raw).stat().st_size > 16 << 20: raise ValueError('input capacity')
    result=analyze(json.loads(Path(args.record).read_text()), Path(args.raw).read_bytes())
    with Path(args.output).open('x') as stream: json.dump(result, stream, indent=2)
    print(json.dumps(dict(quality=result['quality']['status'], candidates=len(result['candidates']), holder_coverage='NOT_IMPLEMENTED')))
