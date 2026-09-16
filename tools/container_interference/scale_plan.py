#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Freeze the S6 matrix; refuse performance admission without a valid S2 gate."""
import argparse
import hashlib
import json
import pathlib
from acceptance import performance_gate


def matrix():
    cases=[]
    for count in (1,12,24,48):
        for round_number in range(1,6):
            for family,seconds,base_modes in (('ambient',15,('off','ip')),
                                              ('diagnostic',2,('off','ip','diag'))):
                modes=base_modes if round_number%2 else tuple(reversed(base_modes))
                for workload in ('bench','open-loop'):
                    for mode in modes:
                        cases.append({'family':family,'count':count,'round':round_number,'mode':mode,'workload':workload,
                                      'target':round_number%count,'bystander':(round_number+1)%count if count>1 else None,
                                      'seconds':seconds,
                                      'required_window_check':'diagnostic attachment/detachment versus actual workload interval; reject incomplete coverage' if mode=='diag' else 'all containers cover the planned interval'})
    return cases


if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--ambient-result',type=pathlib.Path,required=True)
    p.add_argument('--output',type=pathlib.Path,required=True)
    a=p.parse_args();raw=a.ambient_result.read_bytes();gate=json.loads(raw)
    accepted=(gate.get('pass') is True and gate.get('coverage_valid') is True and
              performance_gate('S2','ambient_throughput',[gate]) and
              performance_gate('S2','ambient_p99',[gate]))
    result={'version':2,'status':'READY_FOR_WINDOW_VALIDATION' if accepted else 'BLOCKED',
            'reason':'Diagnostic windows must be validated before their cost is accepted.' if accepted else 'Ambient overhead/coverage prerequisite not accepted; no performance execution authorized by this plan.',
            'ambient_result_sha256':hashlib.sha256(raw).hexdigest(),'cases':matrix(),
            'idle_counts':[128,256],'same_kernel':True,'minimum_vcpus':49,
            'tail_definition':'fixed offered rate; response from scheduled arrival; retain backlog/timeouts',
            'thresholds':{'ambient_throughput_percent':1,'ambient_p99_percent':2,'diagnostic_throughput_percent':3},
            'forbidden':['discard_failed_rounds','relabel_vm_as_baremetal','dilute_diagnostic_cost_over_longer_window',
                         'compare_different_duration_families']}
    with a.output.open('x') as f: json.dump(result,f,indent=2);f.write('\n')
    print(result['status'])
    raise SystemExit(0 if accepted else 1)
