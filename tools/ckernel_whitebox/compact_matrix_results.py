"""Retain calculations and per-copy guardrail inputs, not full replay/log archives."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
from analyze_matrix import summarize


def main():
    p=argparse.ArgumentParser()
    p.add_argument('state');p.add_argument('output')
    args=p.parse_args()
    source=Path(args.state)
    state=json.loads(source.read_text())
    summary,_=summarize(state,formal=True)
    d=Path(args.output);d.mkdir(parents=True,exist_ok=False)
    compact=dict(original_state_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                 summary=summary, runs=[])
    for r in state['runs']:
        row={k:r[k] for k in ('round','variant','copies','status','target_s','batch_s',
                             'config_sha256','image_sha256','target_overlap_fractions','start_spread_ms')}
        row['per_copy']=[dict(slot=c['slot'], duration_s=c['duration_s'],
            first_action_ns=c['action_intervals'][0]['start_ns'], last_action_ns=c['action_intervals'][-1]['end_ns'],
            replay_exit=c['replay_exit'], correctness=c['status'],official=c['official'],
            cpu=c['cpu_stat'], memory_peak_bytes=c['memory_peak_bytes'],io=c['io_stat']) for c in r['per_copy']]
        compact['runs'].append(row)
    (d/'minimal-data.json').write_text(json.dumps(compact,indent=2))
    keys=['workload','scale','baseline_interference_pct','candidate_interference_pct','change_pp',
          'baseline_solo_s','candidate_solo_s','baseline_loaded_s','candidate_loaded_s','correctness','status']
    with (d/'interference.csv').open('w') as f:
        writer=csv.DictWriter(f,fieldnames=keys,extrasaction='ignore');writer.writeheader();writer.writerow(summary)
    print(json.dumps({'path':str(d),'runs':len(compact['runs']),
                      'copies_checked':sum(len(r['per_copy']) for r in compact['runs'])}))


if __name__=='__main__':main()
