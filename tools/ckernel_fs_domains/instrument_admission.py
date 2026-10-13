#!/usr/bin/env python3
"""Independent timing-quality admission for the lighter OFF summary collector."""
import fcntl
import json
import os
from pathlib import Path
import go_fs_matrix as matrix
from fs_domain_lifecycle import save

def main():
    os.umask(0o077)
    os.sched_setaffinity(0, {112, 113, 114, 115})
    lock = (matrix.ROOT / 'matrix.lock').open('a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    root = matrix.ROOT / 'instrument-r6'
    root.mkdir()
    m, inputs = matrix.admission.load()
    plan = [dict(name=f'instrument-d{d}-n{n}', domains=d, n=n, block=0, rotation=0)
            for d in (1, 24) for n in (1, 24)]
    save(root / 'plan.json', dict(phase='instrumentation-admission', states=plan, inputs=inputs,
        maximum_sampler_cpu_ns=50_000_000, maximum_end_offset_ns=150_000_000,
        note='Timing-quality gate only, not proof that the observer has no business impact.'))
    results = []
    for spec in plan:
        row = matrix.execute(m, root, spec)
        window = json.loads((root / spec['name'] / 'window.json').read_text())
        end = max(v['end_ns'] for v in row['business']['instances'])
        row['quality'] = dict(sampler_cpu_ns=window['sampler_cpu_ns'],
                              end_offset_ns=window['after']['end_ns'] - end)
        row['quality_pass'] = (0 <= row['quality']['end_offset_ns'] <= 150_000_000 and
                               row['quality']['sampler_cpu_ns'] <= 50_000_000)
        results.append(row)
        save(root / 'progress.json', results)
        print(json.dumps(dict(spec=spec, quality=row['quality'], passed=row['quality_pass'])), flush=True)
    result = dict(status='PASS' if all(v['quality_pass'] for v in results) else 'FAIL',
                  phase='instrumentation-admission', results=results, states=len(results), copies=50)
    save(root / 'summary.json', result)
    if result['status'] != 'PASS':
        raise RuntimeError('measurement quality not admitted')

if __name__ == '__main__':
    main()
