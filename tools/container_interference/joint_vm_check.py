#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent four-container raw timing and collector-coexistence audit."""
import argparse
import hashlib
import json
from pathlib import Path

from collector_manifest import COLLECTORS
from owner_report import fields
from prototype_admission import SOURCE_KEYS
from session_check import extract
from source_switches import validate
from unified_report import analyze


def workload(log):
    rows=[fields(v) for v in log.splitlines() if v.startswith('CIS_JOINT_WORK ')]
    samples=[v.split(' ',1)[1] for v in log.splitlines() if v.startswith('CIS_JOINT_LATENCIES ')]
    if len(rows)!=1 or len(samples)!=1: raise ValueError('complete workload timing required')
    values=[int(v) for v in samples[0].split(',')]; row=rows[0]
    if (len(values)!=1500 or values!=sorted(values) or any(v<0 for v in values) or row['errors']!=0 or
            row['offered']!=1500 or row['completed']!=1500 or row['period_ns']!=2_000_000 or row['timeout_ns']!=100_000_000 or
            row['p99_ns']!=values[1484] or row['max_ns']!=values[-1] or row['latency_sum_ns']!=sum(values) or
            row['timeouts']!=sum(v>100_000_000 for v in values) or
            not row['due_start_ns']<=row['begin_ns']<row['end_ns']):
        raise ValueError('arrival-relative latency or correctness mismatch')
    return dict(row,throughput_per_second=1500e9/(row['end_ns']-row['due_start_ns']))


def cpu_snapshot(text):
    result={}
    for line in text.splitlines():
        words=line.split()
        if words and (words[0]=='cpu' or words[0].startswith('cpu') and words[0][3:].isdigit()):
            if len(words)<9: raise ValueError('CPU snapshot incomplete')
            result[words[0]]=[int(v) for v in words[1:9]]
    if not result: raise ValueError('CPU snapshot missing')
    return result


def check(serial,output):
    raw=serial.read_bytes()
    if len(raw)>128<<20: raise ValueError('serial capacity')
    text=raw.decode(); files=extract(text); prefix='/tmp/joint-evidence/'
    def value(name): return json.JSONDecoder().raw_decode(files[prefix+name].lstrip())[0]
    plan=value('plan.json'); declared=value('result.json'); permit=value('permit.json')
    output.mkdir(mode=0o700); errors=[]; states=[]
    modes=['off']+list(COLLECTORS); order=[(r,m) for r in range(3) for m in (modes if r%2==0 else list(reversed(modes)))]
    if (plan['schema']!='cis-x7-joint-plan-v1' or plan['order']!=[list(v) for v in order] or
            plan['modes']!=modes or plan['cpus']!=[0,0,1,1] or plan['workloads']!=['file','file','vma','vma'] or
            plan['targets_by_round']!=[[0,2],[1,3],[0,3]] or plan['captures']!=30 or plan['clock_ticks']<=0):
        raise ValueError('unexpected frozen matrix')
    if declared['source']!=plan['source'] or any(plan['source'][k]!=permit['source'][k] for k in SOURCE_KEYS): errors.append('source_binding')
    if 'CIS_PROFILE_VM_EXIT=0' not in text.splitlines(): errors.append('guest_exit')
    if any(v in text for v in ('Oops:','Kernel panic','BUG: KASAN:','WARNING: CPU:')): errors.append('kernel_warning')
    if len(declared['states'])!=len(order): errors.append('incomplete_matrix')
    for r,mode in order:
        label=mode+str(r); evidence=value(label+'-evidence.json'); measured=[]
        for role in range(4):
            measured.append(workload(files[prefix+label+'-%d.log'%role]))
            if measured[-1]['due_start_ns']!=evidence['start_ns'] or measured[-1]['mode']!=plan['workloads'][role]: errors.append('workload_binding_'+label)
        if evidence['exit_codes']!=[0]*4 or len(set(evidence['all_targets']))!=4: errors.append('four_actors_'+label)
        if evidence['targets']!=[evidence['all_targets'][i] for i in plan['targets_by_round'][r]]: errors.append('role_rotation_'+label)
        cost=None; relations=[]
        if mode!='off':
            sid=evidence['session_id']; record=value('records/'+sid+'.json')
            if record['collector']!=mode or record['nonce']!=label or record['targets']!=evidence['targets']: errors.append('record_binding_'+label)
            if any(record.get(k)!=plan['source'][k] for k in SOURCE_KEYS): errors.append('record_source_'+label)
            capture=(files[prefix+'records/'+sid+'.jsonl'].rstrip()+'\n').encode(); report=analyze(record,capture)
            if report['quality']['status']!='PASS' or report['scope_audit'].get('status','PASS')!='PASS': errors.append('capture_quality_'+label)
            if not record.get('objects_absent'): errors.append('cleanup_'+label)
            if not evidence['start_ns']<record['window']['start_ns']<record['window']['end_ns']<min(v['end_ns'] for v in measured): errors.append('window_coverage_'+label)
            validate(evidence['active_sources'],mode,record['receipt']['prepared_ns'],record['window']['end_ns'])
            validate(evidence['idle_sources'],None,record['window']['end_ns'],2**64-1)
            relations=report['relations']; cost=dict(process_cpu=record.get('process_cpu_budget'),
                memory=record.get('memory'),rss_bytes=record.get('combined_rss_peak_bytes'),
                explicit_unknown=['business-context callback CPU not separately measured','kernel asynchronous memory not complete'])
            (output/(label+'-explanation.json')).write_text(json.dumps(report,indent=2))
        else:
            if evidence['session_id'] is not None: errors.append('off_capture')
            validate(evidence['active_sources'],None,0,2**64-1); validate(evidence['idle_sources'],None,0,2**64-1)
        a=cpu_snapshot(evidence['before']['proc_stat']); b=cpu_snapshot(evidence['after']['proc_stat'])
        if a.keys()!=b.keys(): errors.append('cpu_set_changed')
        cpu={k:[q-p for p,q in zip(a[k],b[k])] for k in a if k in b}
        if any(v<0 for row in cpu.values() for v in row): errors.append('cpu_counter_regression')
        states.append(dict(label=label,mode=mode,round=r,workload=measured,cost=cost,relations=len(relations),
            cpu_delta_ticks=cpu,cpu_clock_hz=plan['clock_ticks'],
            cpu_scope='whole benchmark enclosing capture; includes business CPU, not observer-only cost',
            elapsed_ns=evidence['after']['time_ns']-evidence['before']['time_ns'],
            cgroup_memory_after=[v['memory.current'] for v in evidence['after']['roots']]))
    comparisons=[]
    for r in range(3):
        off=next(s for s in states if s['round']==r and s['mode']=='off')
        for state in (s for s in states if s['round']==r and s['mode']!='off'):
            for role in range(4):
                a,b=off['workload'][role],state['workload'][role]
                comparisons.append(dict(round=r,mode=state['mode'],actor=role,
                    role='target' if role in plan['targets_by_round'][r] else 'bystander',
                    throughput_change_fraction=b['throughput_per_second']/a['throughput_per_second']-1,
                    p99_change_fraction=None if not a['p99_ns'] else b['p99_ns']/a['p99_ns']-1,
                    p99_change_ns=b['p99_ns']-a['p99_ns'],timeouts_before=a['timeouts'],timeouts_after=b['timeouts']))
    result=dict(schema='cis-x7-joint-check-v1',status='FAIL' if errors else 'PASS_SCOPED',errors=sorted(set(errors)),
        states=states,comparisons=comparisons,serial_sha256=hashlib.sha256(raw).hexdigest(),source=plan['source'],
        x7_complete=False,scope='four-container mixed native operations with fixed offered load',
        limits=['no population attribution precision/recall without full truth','quiet adapters do not gain positive coverage',
                'not saturated-throughput or tail-latency acceptance','whole VM CPU includes business and background'],
        performance_certification='NOT_ACCEPTED')
    (output/'verification.json').write_text(json.dumps(result,indent=2)); return result


if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('serial',type=Path); p.add_argument('output',type=Path); a=p.parse_args()
    result=check(a.serial,a.output)
    print(json.dumps(dict(status=result['status'],errors=result['errors'],states=len(result['states']))))
    raise SystemExit(result['status']=='FAIL')
