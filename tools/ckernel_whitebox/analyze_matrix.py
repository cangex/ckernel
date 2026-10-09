"""Compact paired workload summaries; no causal claims from elapsed time alone."""
import argparse
import csv
import json
import math
from pathlib import Path
import statistics

T95 = {2:4.303, 3:3.182, 4:2.776, 5:2.571, 6:2.447, 7:2.365, 8:2.306, 9:2.262, 10:2.228, 11:2.201}


def interval(ratios):
    logs = [math.log(v) for v in ratios]
    n = len(logs)
    assert n >= 3
    mean = statistics.mean(logs)
    half = T95[n-1]*statistics.stdev(logs)/math.sqrt(n)
    return dict(geometric_percent=100*math.expm1(mean), low_percent=100*math.expm1(mean-half),
                high_percent=100*math.expm1(mean+half), n=n)


def summarize(state, formal=False):
    assert state['status'] == 'PASS' and all(r['status']=='PASS' for r in state['runs'])
    index = {(r['round'],r['variant'],r['copies']): r for r in state['runs']}
    assert len(index)==len(state['runs'])
    rounds = sorted({r['round'] for r in state['runs']})
    assert len(index) == len(rounds)*4
    means = {(v,n): statistics.mean(index[r,v,n]['target_s'] for r in rounds)
             for v in ('baseline','candidate') for n in (1,12)}
    interference = {v:100*(means[v,12]/means[v,1]-1) for v in ('baseline','candidate')}
    ratios = {}
    for n in (1,12):
        ratios['target_'+str(n)] = [index[r,'candidate',n]['target_s']/index[r,'baseline',n]['target_s'] for r in rounds]
        ratios['batch_'+str(n)] = [index[r,'candidate',n]['batch_s']/index[r,'baseline',n]['batch_s'] for r in rounds]
        ratios['worst_copy_'+str(n)] = [max(c['duration_s']/b['duration_s'] for b,c in zip(
            index[r,'baseline',n]['per_copy'], index[r,'candidate',n]['per_copy'])) for r in rounds]
        for field, key in [('memory_peak_bytes','peak_sum'),('cpu_stat','cgroup_cpu')]:
            def total(record):
                return sum(p[field]['usage_usec'] if field=='cpu_stat' else p[field] for p in record['per_copy'])
            ratios[key+'_'+str(n)] = [total(index[r,'candidate',n])/total(index[r,'baseline',n]) for r in rounds]
    cis = {k:interval(v) for k,v in ratios.items()}
    result = dict(workload=state['runs'][0]['workload'], rounds=len(rounds), scale=12,
        baseline_solo_s=means['baseline',1], candidate_solo_s=means['candidate',1],
        baseline_loaded_s=means['baseline',12], candidate_loaded_s=means['candidate',12],
        baseline_interference_pct=interference['baseline'], candidate_interference_pct=interference['candidate'],
        change_pp=interference['candidate']-interference['baseline'],
        absolute_loaded_change_pct=100*(means['candidate',12]/means['baseline',12]-1),
        paired_intervals=cis, correctness='PASS', status='EXPLORATORY_ONLY',
        limits=['single shared KVM guest, not bare-metal NUMA',
                'cgroup CPU includes startup before barrier, excludes grading',
                'peak sum is not whole-VM memory; host backend attribution incomplete',
                'elapsed-time changes do not prove inode lock contribution'])
    if formal:
        benefit = result['absolute_loaded_change_pct'] <= -3 and cis['target_12']['high_percent'] < 0
        harm = [k for k in ('target_1','batch_1','batch_12','worst_copy_1','worst_copy_12') if cis[k]['low_percent']>2]
        safe = all(cis[k]['high_percent']<=2 for k in ('target_1','batch_1','batch_12','worst_copy_1','worst_copy_12'))
        cost_ok = all(cis[k]['high_percent']<=5 for k in ('cgroup_cpu_1','cgroup_cpu_12','peak_sum_1','peak_sum_12'))
        result['status'] = 'COST_TRANSFER_OR_REGRESSION' if harm else ('PARTIAL_GATES_PASS_BACKEND_COST_UNRESOLVED' if benefit and safe and cost_ok else 'NET_BENEFIT_NOT_ESTABLISHED')
        result['failed_harm_bounds'] = harm
    return result, ratios


def main():
    p = argparse.ArgumentParser()
    p.add_argument('state'); p.add_argument('output')
    p.add_argument('--freeze-formal', action='store_true');p.add_argument('--formal', action='store_true')
    args = p.parse_args()
    state = json.loads(Path(args.state).read_text())
    summary, ratios = summarize(state, args.formal)
    d = Path(args.output); d.mkdir(exist_ok=False)
    (d/'summary.json').write_text(json.dumps(summary,indent=2))
    with (d/'interference.csv').open('w') as f:
        keys = ['workload','scale','baseline_interference_pct','candidate_interference_pct','change_pp','baseline_solo_s','candidate_solo_s','baseline_loaded_s','candidate_loaded_s','correctness','status']
        w = csv.DictWriter(f,fieldnames=keys,extrasaction='ignore'); w.writeheader();w.writerow(summary)
    if args.freeze_formal:
        # Independent pilot variance, not a sequential significance stopping rule.
        sd = max(statistics.stdev(math.log(x) for x in ratios[k]) for k in ('target_1','target_12','batch_12'))
        requested = math.ceil((2.8*sd/math.log(1.03))**2)
        n = min(12,max(5,requested))
        plan = dict(workload=summary['workload'], blocks=n, variance_estimate=sd,
                    requested_normal_approximation=requested, capped=requested>12,
                    primary_minimum_improvement_pct=3, bystander_bound_pct=2, cpu_memory_bound_pct=5,
                    ci='paired log ratios, two-sided t 95%; no significance-driven extension',
                    order=[(r,v,count) for r in range(1,n+1) for count in ((1,12) if r%2 else (12,1))
                           for v in (('baseline','candidate') if r%2 else ('candidate','baseline'))])
        (d/'formal-plan.json').write_text(json.dumps(plan,indent=2))
    print(json.dumps(summary),flush=True)


if __name__ == '__main__':
    main()
