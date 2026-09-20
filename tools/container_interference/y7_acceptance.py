# SPDX-License-Identifier: GPL-2.0
"""Independently replay both Y7 cohorts; summarize, never certify production cost."""
import argparse
import hashlib
import json
import os
from pathlib import Path
from session_check import extract
import y7_private_check
import y7_queue_check

def span(values):
    return [min(values),max(values)] if values else None

def matrix(receipt):
    if receipt.get('status')!='PASS_SCOPED' or len(receipt.get('states',[]))!=9:
        raise ValueError('incomplete accepted cohort')
    expected=y7_private_check.order()
    if [{k:s[k] for k in ('round','mode','label')} for s in receipt['states']]!=expected:
        raise ValueError('frozen matrix changed')
    collectors=y7_private_check.captures if receipt['cohort']=='private_storage' else y7_queue_check.captures
    if receipt['arrangement'] not in ('shared','separate'): raise ValueError('placement')
    for state in receipt['states']:
        if state['status']!='PASS_SCOPED' or state['errors'] or len(state['workloads'])!=4:
            raise ValueError('state correctness')
        if tuple(o['collector'] for o in state['observations'])!=collectors(state['mode']):
            raise ValueError('missing collector')
        if any(o['quality']['status']!='PASS' for o in state['observations']): raise ValueError('quality failure')
    if len(receipt['comparisons'])!=24: raise ValueError('paired population')

def summary(receipt):
    matrix(receipt);cost=[];coverage={}
    for mode in ('off','survey','profile'):
        states=[s for s in receipt['states'] if s['mode']==mode]
        management=[s['system_cost']['management'] for s in states]
        row=dict(mode=mode,
            management_cpu_ms=[m['cpu_delta_usec']['usage_usec']/1000 for m in management],
            management_cumulative_peak_bytes=max(m['cumulative_memory_peak_start_end_bytes'][1] for m in management),
            management_end_components_bytes={k:span([m['memory_stat_start_end'][1][k] for m in management])
                if all(k in m['memory_stat_start_end'][1] for m in management) else None
                for k in ('anon','file','kernel','slab','kernel_stack','pagetables')},
            business_cpu_ms=[sum(a['cpu_delta_usec']['usage_usec'] for a in s['system_cost']['actors'])/1000 for s in states],
            kernel_thread_ticks=[s['system_cost']['kernel_threads']['matched_cpu_ticks'] for s in states],
            kernel_thread_clock_hz=[s['system_cost']['kernel_threads']['clock_hz'] for s in states],
            timeouts=sum(w['timeouts'] for s in states for w in s['workloads']))
        for role in ('target','bystander'):
            cells=[c for c in receipt['comparisons'] if c['mode']==mode and c['role']==role]
            row[role]=dict(p99_delta_ms=span([c['p99_delta_ns']/1e6 for c in cells]),
                throughput_fraction=span([c['throughput_change'] for c in cells]))
        cost.append(row)
        for s in states:
            for o in s['observations']:
                c=coverage.setdefault(o['collector'],dict(captures=0,accepted_relations=0,coverage=[],rss_bytes=[]))
                c['captures']+=1;c['accepted_relations']+=len(o['relations']);c['coverage'].append(o['coverage'])
                c['rss_bytes'].append(o['rss_bytes'])
    return dict(cohort=receipt['cohort'],arrangement=receipt['arrangement'],cost=cost,coverage=coverage,
        limits=receipt['limits'])

def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1<<20),b''):h.update(chunk)
    return h.hexdigest()

def first_analysis_timing(state,checked,records):
    """Use the retained guest analysis, never a replay host's monotonic clock."""
    observations=checked['observations'];sessions=state['sessions'];result=[]
    if len(observations)!=len(records) or len(sessions)!=len(records):
        raise ValueError('first-analysis population')
    for session,observation,record in zip(sessions,observations,records):
        t=observation['report_timing'];w=record['window'];done=t.get('explained_at_ns')
        if (observation['collector']!=record['collector'] or session['collector']!=record['collector'] or
                str(session['session_id'])!=str(record['session_id']) or
                observation['quality']['status']!='PASS' or
                t.get('analysis_boot_id')!=record['boot_id'] or not t.get('same_clock_as_capture') or
                type(done) is not int or not w['end_ns']<=done<=state['explanation_ready_ns'] or
                t.get('explanation_lag_ns')!=done-w['end_ns'] or
                not session['scheduled_ns']<=record['requested_ns']<=w['start_ns']<w['end_ns']):
            raise ValueError('first-analysis clock or capture binding')
        result.append(dict(collector=record['collector'],session_id=record['session_id'],
            scheduled_to_request_ns=record['requested_ns']-session['scheduled_ns'],
            request_to_window_ns=w['start_ns']-record['requested_ns'],
            window_end_to_first_explanation_ns=done-w['end_ns'],
            periodic_detection_wait='NOT_MEASURED',
            boundary='frozen schedule; harness analyzes after workload completion, not automatic discovery'))
    return result

def run(storage,network,output):
    os.umask(0o077);out=Path(output);out.mkdir(mode=0o700)
    receipts=[];proofs=[];images=set()
    for cohort,root,checker,prefix in (
            ('private_storage',Path(storage),y7_private_check,'/tmp/y7-private-evidence/'),
            ('private_connections',Path(network),y7_queue_check,'/tmp/y7-queue-evidence/')):
        for arrangement in ('shared','separate'):
            source=root/arrangement;logs=list(source.glob('y7-*.log'));manifests=list(source.glob('*.manifest.json'))
            if len(logs)!=1 or len(manifests)!=1: raise ValueError('unique immutable VM artifacts required')
            serial=logs[0];manifest=json.loads(manifests[0].read_text())
            if manifest.get('source_diagnostics') or not manifest.get('performance_eligible') or manifest.get('scope')!='isolated_KVM_only':
                raise ValueError('diagnostic-only or invalid VM scope')
            images.add(manifest['image_sha256'])
            dest=out/(cohort+'-'+arrangement)
            checker.replay(serial,dest)
            receipt=json.loads((dest/'verification.json').read_text());matrix(receipt)
            if receipt['arrangement']!=arrangement or receipt['cohort']!=cohort: raise ValueError('cohort binding')
            files=extract(serial.read_text());analysis_peaks=[];timing=[];process=[];first_timing=[]
            for entry in y7_private_check.order():
                state=json.JSONDecoder().raw_decode(files[prefix+entry['label']+'-evidence.json'].lstrip())[0]
                analysis_peaks.append(state['analysis_process']['peak_rss_bytes'])
                if not state['business_after']['read_end_ns']<state['explanation_ready_ns']<=state['after']['time_ns']:
                    raise ValueError('first-analysis cost boundary')
                timing.append(dict(label=entry['label'],business_to_explanation_ns=state['explanation_ready_ns']-state['business_after']['time_ns']))
                records=[]
                for session in state['sessions']:
                    record=json.JSONDecoder().raw_decode(files[prefix+'records/'+session['session_id']+'.json'].lstrip())[0]
                    records.append(record)
                    process.append(dict(collector=session['collector'],budget=record['process_cpu_budget']))
                checked=json.JSONDecoder().raw_decode(files[prefix+entry['label']+'-check.json'].lstrip())[0]
                first_timing.append(dict(label=entry['label'],captures=first_analysis_timing(state,checked,records)))
            s=summary(receipt);s['analysis_harness_cumulative_rss_peak_bytes']=max(analysis_peaks)
            s['analysis_boundary_timing']=timing;s['first_analysis_timing']=first_timing
            s['process_cpu_budgets']=process;receipts.append(s)
            proofs.append(dict(serial=str(serial.resolve()),serial_sha256=sha(serial),manifest_sha256=sha(manifests[0]),
                source_head=manifest['source_head'],initrd_sha256=manifest['initrd_sha256'],replay=str(dest.resolve())))
            del files,receipt
    if len(images)!=1:raise ValueError('cohorts used different native kernels')
    result=dict(schema='cis-y7-joint-replay-v1',status='PASS_SCOPED',states=36,captures=66,
        cohorts=receipts,proofs=proofs,image_sha256=next(iter(images)),
        performance_certification='NOT_ACCEPTED',stage_coverage_reconciliation_required=True,
        limits=['four accounting roots, at most two active profile targets, eight-vCPU isolated VM',
            'fixed-rate throughput is not saturated service capacity; P99 record-only',
            'manager includes harness, preparation and first analysis; excludes final export/replay',
            'cgroup cumulative peak includes resident processes and file cache; not per-capture RSS',
            'whole-VM deltas include unrelated background; complete observer-exclusive CPU/memory unknown',
            'preplanned source windows do not prove automatic trigger or wall-clock discovery latency',
            'E1/E2 relations are not E3 causality; hardware SPE remains unsupported'])
    (out/'joint-acceptance.json').write_text(json.dumps(result,indent=2))
    return dict(status=result['status'],states=36,captures=66,performance_certification='NOT_ACCEPTED')

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('storage');p.add_argument('network');p.add_argument('output')
    a=p.parse_args();print(json.dumps(run(a.storage,a.network,a.output)))
