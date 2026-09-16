#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Check decoded sample coverage and migration against the guest monotonic clock."""
import argparse
import collections
import json
import pathlib
import re
FIELDS = re.compile(r'(\w+)=([^ ;]+)')


def analyze(text):
    records, errors, begin, end = [], [], None, None
    for line in text.splitlines():
        if line.startswith('CIS_MIGRATION_BEGIN '):
            begin = {k: int(v) for k, v in FIELDS.findall(line)}
        elif line.startswith('CIS_MIGRATION_END '):
            end = {k: int(v) for k, v in FIELDS.findall(line)}
        elif line.startswith('{'):
            try:
                record = json.loads(line)
            except ValueError:
                errors.append('invalid_json')
                continue
            if 'kind' in record:
                records.append(record)
    counts = collections.Counter(x['kind'] for x in records)
    for record in records:
        fields = dict(FIELDS.findall(record.get('detail', '')))
        if record['kind'] in ('sample_schema_error','capture_failure','capture_error','budget_disable','buffer_loss'):
            errors.append(record)
        if record['kind'] == 'budget' and (int(fields.get('errors','0')) or int(fields.get('drops','0'))):
            errors.append(record)
    pre, post, wrong = 0, 0, []
    if begin and end:
        for r in records:
            if r['kind'] != 'IP':
                continue
            f = dict(FIELDS.findall(r['detail']))
            if int(f['tid']) & 0xffffffff != begin['tid']:
                continue
            t = int(f['sample_time_ns'])
            if t < begin['time_ns']:
                pre += 1
                if r['id'] != begin['from']:
                    wrong.append(r)
            elif t > end['time_ns']:
                post += 1
                if r['id'] != begin['to']:
                    wrong.append(r)
    return {'version': 1, 'record_counts': dict(counts), 'errors': errors,
            'migration_begin': begin, 'migration_end': end,
            'migration_pre_samples': pre, 'migration_post_samples': post,
            'migration_wrong_root': wrong,
            'pass': counts['IP']>0 and pre>0 and post>0 and not errors and not wrong,
            'boundary': 'Samples inside the cgroup.procs migration interval are not assigned a forced ordering.'}


if __name__ == '__main__':
    p=argparse.ArgumentParser()
    p.add_argument('log',type=pathlib.Path)
    p.add_argument('output',type=pathlib.Path)
    a=p.parse_args()
    result=analyze(a.log.read_text())
    with a.output.open('x') as f:
        json.dump(result,f,indent=2)
        f.write('\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('errors','migration_wrong_root')},indent=2))
    raise SystemExit(not result['pass'])
