#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Join one monotonic-clock capture to independent, predeclared episode truth."""
import argparse
import hashlib
import json
from pathlib import Path
import re
from detection_latency import gate

FIELDS = re.compile(r'(\w+)=([^ ;]+)')
WARNINGS = {'FAST_ALERT', 'FAST_LOCK_CANDIDATE', 'E0'}
BAD = {'budget_disable', 'metrics_budget_disable', 'capture_failure',
       'capture_error', 'buffer_loss', 'fast_source_error', 'entry_budget_disable'}


def analyze(truth, events):
    if truth.get('version') != 1 or truth.get('clock') != 'CLOCK_MONOTONIC':
        raise ValueError('one capture and independent monotonic episode truth required')
    if truth.get('independent_truth') is not True or not truth.get('run_id'):
        raise ValueError('truth cannot be derived from observer alerts')
    episodes = truth.get('episodes', [])
    seen = set()
    for episode in episodes:
        if not episode.get('episode_id') or episode['episode_id'] in seen:
            raise ValueError('missing or duplicate episode id')
        seen.add(episode['episode_id'])
        for key in ('id', 'generation', 'start_ns', 'end_ns'):
            if type(episode.get(key)) is not int or episode[key] < 0:
                raise ValueError('invalid episode identity or time')
        if episode['end_ns'] <= episode['start_ns']:
            raise ValueError('empty episode')
        if type(episode.get('positive')) is not bool or type(episode.get('free_slot')) is not bool:
            raise ValueError('explicit truth polarity and diagnosis-slot eligibility required')
    # Overlapping truths cannot silently share the same warning or relation.
    for i, a in enumerate(episodes):
        for b in episodes[i + 1:]:
            if ((a['id'], a['generation']) == (b['id'], b['generation']) and
                    max(a['start_ns'], b['start_ns']) < min(a['end_ns'], b['end_ns'])):
                raise ValueError('overlapping truth for one identity')
    quality = [e for e in events if e.get('kind') in BAD]
    rows = []
    for ep in episodes:
        matched = sorted((e for e in events if
                          (e.get('id'), e.get('generation')) == (ep['id'], ep['generation']) and
                          ep['start_ns'] <= e.get('time_ns', -1) < ep['end_ns']),
                         key=lambda e: e['time_ns'])
        warnings = [e for e in matched if e.get('kind') in WARNINGS]
        warning = warnings[0]['time_ns'] if warnings else None
        starts = [e for e in matched if e.get('kind') == 'diagnostic_start' and
                  warning is not None and e['time_ns'] >= warning]
        ready = None
        if starts:
            detail = dict(FIELDS.findall(starts[0].get('detail', '')))
            value = detail.get('ready_ns')
            if value and value.isdigit():
                ready = int(value)
                if not warning <= ready <= starts[0]['time_ns']:
                    quality.append({'kind': 'invalid_ready_timestamp', 'episode_id': ep['episode_id']})
                    ready = None
        # A raw OWNER event or co-waiter edge is not a completed holder relation.
        relations = [e for e in matched if e.get('kind') == 'relation' and
                     e.get('protocol_version') == 2 and e.get('relation_type') == 'holder_waiter' and
                     e.get('level') == 'E2' and e.get('causal') is False and
                     e.get('validated') is True]
        relation = relations[0]['time_ns'] if relations else None
        rows.append(dict(ep, warning_ns=warning, diagnosis_ready_ns=ready,
                         warning_delay_ns=warning - ep['start_ns'] if warning is not None else None,
                         candidate_to_ready_ns=ready - warning if ready is not None else None,
                         first_relation_ns=relation,
                         relation_delay_ns=relation - ep['start_ns'] if relation is not None else None,
                         warning_count=len(warnings), relation_count=len(relations)))
    eligible = [x for x in rows if x['positive'] and x['end_ns'] - x['start_ns'] >= 500000000 and
                x.get('supported') is True and x.get('strength_qualified') is True]
    delays = [x['warning_delay_ns'] for x in eligible]
    # Free-slot truth is external: do not exclude a missed target because no slot was observed.
    ready_delays = [x['candidate_to_ready_ns'] for x in eligible if x['free_slot']]
    gates = {'warning_p95': gate(delays, 250, .95),
             'warning_p99': gate(delays, 500, .99),
             'free_slot_start_p95': gate(ready_delays, 100, .95)}
    negative = [x for x in rows if not x['positive']]
    wrong = sum(x['relation_count'] for x in negative)
    return {'version': 1, 'run_id': truth['run_id'], 'episodes': rows, 'gates': gates,
            'eligible_episodes': len(eligible), 'ineligible_episodes': len(rows) - len(eligible),
            'eligible_warning_recall': sum(x is not None for x in delays)/len(delays) if delays else None,
            'unserved_eligible_episodes': sum(x['diagnosis_ready_ns'] is None for x in eligible),
            'negative_episodes': len(negative),
            'negative_episodes_with_warning': sum(x['warning_count'] > 0 for x in negative),
            'wrong_holder_relations': wrong, 'quality_failures': quality,
            'latency_gate_pass': not quality and not wrong and all(x['status'] == 'PASS' for x in gates.values()),
            'release_accepted': False,
            'limitations': ['Latency alone does not establish cost, accuracy, recall or production coverage.',
                            'Candidate-to-ready includes queueing and attach work; it is not pure detector time.',
                            'No relation completion timestamp is inferred from raw kernel owner events.',
                            'Cross-episode independence and strength qualification require external validation.']}


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('truth', type=Path); p.add_argument('events', type=Path); p.add_argument('output', type=Path)
    a = p.parse_args()
    raw = a.events.read_bytes(); source = a.truth.read_bytes()
    events = [json.loads(line) for line in raw.splitlines() if line.strip()]
    result = analyze(json.loads(source), events)
    result.update(raw_sha256=hashlib.sha256(raw).hexdigest(), truth_sha256=hashlib.sha256(source).hexdigest())
    with a.output.open('x') as f:
        json.dump(result, f, indent=2); f.write('\n')
    print(json.dumps({'eligible': result['eligible_episodes'], 'gates': result['gates'],
                      'quality_failures': len(result['quality_failures']), 'release_accepted': False}, indent=2))
