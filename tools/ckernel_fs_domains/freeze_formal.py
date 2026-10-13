#!/usr/bin/env python3
"""Freeze one independent formal matrix only after pilot and timing admission."""
import hashlib
import json
import os
from pathlib import Path
import statistics
from fs_domain_lifecycle import save
import go_fs_matrix as matrix

def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    os.umask(0o077)
    pilot_path = matrix.ROOT / 'matrix-pilot-r2/summary.json'
    instrument_path = matrix.ROOT / 'instrument-r3/summary.json'
    pilot = json.loads(pilot_path.read_text())
    instrument = json.loads(instrument_path.read_text())
    assert pilot['status'] == 'PASS' and pilot['states'] == 24 and pilot['copies'] == 300
    assert instrument['status'] == 'PASS' and all(v['quality_pass'] for v in instrument['results'])
    variability = {}
    for d in (1, 2, 4, 24):
        values = [r['business']['target_s'] for r in pilot['results'] if r['spec']['domains'] == d and r['spec']['n'] == 24]
        assert len(values) == 3
        variability[str(d)] = dict(mean=statistics.mean(values), cv=statistics.stdev(values) / statistics.mean(values))
    output = matrix.ROOT / 'formal-freeze-r1.json'
    if output.exists():
        raise RuntimeError('formal protocol already frozen')
    result = dict(admitted=True, states=matrix.plan('formal'), blocks=8,
        pilot_sha256=digest(pilot_path), instrumentation_sha256=digest(instrument_path),
        matrix_sha256=digest(Path(matrix.__file__)), pilot_loaded_variability=variability,
        decision='Eight predefined order-balanced paired blocks. No significance-driven extension.',
        precision_limit='Three pilot blocks do not establish power for 2% noninferiority; wide intervals stay unresolved.',
        statistics='Paired log ratios; Student t with df=7; two-sided 98.3333% intervals per candidate versus shared-1.',
        retention=dict(primary_ratio_at_most=.97, primary_interval_high_below=1,
                       solo_peers_each_slot_batch_interval_high_at_most=1.02,
                       cpu_memory_interval_high_at_most=1.05),
        restrictions=['No pilot values pooled with formal data.', 'No business workload, binding or topology change.',
                      'Host/background counters include unrelated work; no complete ownership claim.',
                      'Target/time qualification alone is not full-system net-benefit acceptance.'])
    save(output, result)
    print(json.dumps(result), flush=True)

if __name__ == '__main__':
    main()
