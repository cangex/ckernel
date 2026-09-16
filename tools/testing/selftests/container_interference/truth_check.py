#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Validate fixture observations without upgrading them to general lock ownership."""
import argparse
import json
import pathlib
import re

PAIR = re.compile(r'(\w+)=([^ ;]+)')


def parse(text):
    truth, observations, objects, parse_errors = [], [], set(), []
    scenario = None
    for line in text.splitlines():
        if line.startswith('CIS_FILE /tmp/truth-'):
            scenario = 'private' if 'private' in line else 'shared'
        elif line.startswith('CIS_TRUTH '):
            entry = dict(PAIR.findall(line))
            entry['scenario'] = scenario
            if not all(k in entry for k in ('begin_ns','acquired_ns','released_ns','cgroup_id','object')):
                parse_errors.append(line)
                continue
            for key in ('begin_ns', 'acquired_ns', 'released_ns', 'cgroup_id'):
                entry[key] = int(entry[key])
            truth.append(entry)
            objects.add(entry['object'])
        elif line.startswith('{'):
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if record.get('kind') == 'E1':
                item = dict(PAIR.findall(record['detail']))
                if item.get('type') == '3':
                    item.update(root=record['id'], emitted_ns=record['time_ns'])
                    observations.append(item)
    matched, missed, latencies, bad = 0, [], [], []
    positives = [x for x in truth if x['acquired_ns']-x['begin_ns'] >= 50000]
    for event in positives:
        candidates = [o for o in observations if o['object'] == event['object'] and o['root'] == event['cgroup_id']
                      and event['begin_ns'] <= int(o['sample_time_ns']) <= event['acquired_ns']
                      and int(o['sample_time_ns'])+int(o['duration_ns']) <= event['acquired_ns']+50000]
        if candidates:
            matched += 1
            latencies.append(min(x['emitted_ns'] for x in candidates)-event['acquired_ns'])
        else:
            missed.append(event)
    considered = [o for o in observations if o['object'] in objects]
    for item in considered:
        same = [x for x in truth if x['object'] == item['object'] and x['cgroup_id'] == item['root']
                and x['begin_ns'] <= int(item['sample_time_ns']) <= x['acquired_ns']]
        if not same:
            bad.append(item)
    return {'version': 2, 'parse_errors':parse_errors, 'truth_operations': len(truth), 'positive_waits_at_least_50us': len(positives),
            'matched': matched, 'missed': missed, 'false_identity_or_interval': bad,
            'recall': matched/len(positives) if positives else None,
            'precision_within_fixture_objects': (len(considered)-len(bad))/len(considered) if considered else None,
            'observation_delivery_ns': latencies,
            'owner_unknown_rate': 1.0,
            'automatic_discovery_latency': None,
            'limitations': ['Manual diagnostic window, not automatic detection recall.',
                            'Ground truth covers two static mutex objects only; not arbitrary spinlocks.',
                            'Other recorded locks may belong to test logging or kernel paths and are not ground-truth negatives.'],
            'pass': len(truth) == 800 and len(positives) > 100 and not missed and not bad and not parse_errors}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('log', type=pathlib.Path)
    parser.add_argument('output', type=pathlib.Path)
    args = parser.parse_args()
    result = parse(args.log.read_text())
    with args.output.open('x') as dest:
        json.dump(result, dest, indent=2)
        dest.write('\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('missed','observation_delivery_ns','false_identity_or_interval')},indent=2))
    raise SystemExit(0 if result['pass'] else 1)
