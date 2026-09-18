#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Evidence-based checks; absent coverage is BLOCKED, never success by wording."""
import argparse
import json
from pathlib import Path
import re
import statistics
import owner_report
from session_quality import assess


def extract(text):
    files={};current=None
    for line in text.splitlines():
        if line == 'CIS_FILES_END' or re.fullmatch(r'\[\s*[\d.]+\]\s*(?:\[\s*T\d+\]\s*)?reboot: Power down', line):
            # Old guests lack an end sentinel. Their final poweroff line is
            # followed by QMP JSON, not by more artifact content.
            current=None
        elif line.startswith('CIS_FILE '):
            current=line.split(' ',1)[1]
            if current in files:raise ValueError('duplicate raw artifact path: '+current)
            files[current]=[]
        elif current:
            files[current].append(line)
    return {name:'\n'.join(lines) for name,lines in files.items()}


def numbers(line):
    return {key:int(value,0) for key,value in re.findall(r'(\w+)=(-?0x[\da-fA-F]+|-?\d+)',line)}


def cost_protocol(text, files):
    headers = [json.loads(line.split(' ',1)[1]) for line in text.splitlines()
               if line.startswith('CIS_PROFILE_COST_PROTOCOL ')]
    if not headers:
        return dict(version=1, warmup_operations=0, diagnostic_window_p99_target_pct=None)
    if len(headers)!=1:
        raise ValueError('one frozen cost protocol required')
    protocol=headers[0]
    if protocol.get('version')==1:
        if protocol.get('warmup_operations')!=0:
            raise ValueError('legacy protocol cannot claim warmup')
        return protocol
    expected=dict(version=2,pairs=5,warmup_operations=4096,window_ms=2000,
                  timer_slack='inherited_default',arrival_rate=2000,no_tracing=True,
                  diagnostic_window_p99_target_pct=2)
    if any(protocol.get(k)!=v for k,v in expected.items()):
        raise ValueError('unsupported cost protocol')
    seen=set()
    for name,body in files.items():
        match=re.search(r'cost-(throughput|latency)-(\d+)-(off|idle|ip|owner)-(\d)\.log$',name)
        if not match:continue
        key=match.groups()
        if key in seen:raise ValueError('duplicate warm cost cell')
        seen.add(key)
        warm=[numbers(x) for x in body.splitlines() if x.startswith('CIS_WARMUP ')]
        result=[numbers(x) for x in body.splitlines() if x.startswith(('CIS_RESULT ','CIS_LATENCY '))]
        if len(warm)!=1 or len(result)!=1 or warm[0].get('operations')!=4096 or warm[0].get('before_start')!=1 or warm[0]['end_ns']>=result[0]['start_ns']:
            raise ValueError('warmup boundary missing or late')
        if any(x.startswith('CIS_LATENCY_SAMPLE ') for x in body.splitlines()):
            raise ValueError('traced timeline is not cost acceptance')
    required={(w,str(r),m,str(role)) for w in ('throughput','latency') for r in range(5)
              for m in ('off','idle','ip','owner') for role in range(2)}
    if seen!=required:raise ValueError('incomplete frozen warm cost batch')
    return protocol


def interval(values):
    if len(values)!=5:return {'n':len(values),'status':'BLOCKED'}
    mean=statistics.mean(values);half=2.776445105*statistics.stdev(values)/len(values)**.5
    return {'n':5,'mean_pct':mean,'lower95_pct':mean-half,'upper95_pct':mean+half,'pairs_pct':values}


def capture_quality(records, workload, mode):
    result = []
    for repetition in range(5):
        nonce = ('cost-%s-%d-%s' % (workload, repetition, mode)).replace('-', '')
        matches = [record for record in records.values() if record.get('nonce') == nonce]
        if len(matches) != 1:
            return dict(status='BLOCKED', reason='missing or duplicate capture record', nonce=nonce)
        record = matches[0]
        quality = assess(record)
        result.append(dict(nonce=nonce, complete=quality['status']=='PASS', quality=quality))
    status = ('FAIL' if any(item['quality']['status']=='FAIL' for item in result) else
              'BLOCKED' if any(item['quality']['status']=='BLOCKED' for item in result) else 'PASS')
    return dict(status=status, windows=result)


def analyze(text):
    files=extract(text)
    protocol=cost_protocol(text, files)
    records={}
    for name,body in files.items():
        if '/records/' in name and name.endswith('.json'):
            decoder=json.JSONDecoder()
            try:record=decoder.raw_decode(body.lstrip())[0]
            except ValueError:continue
            records[record['session_id']]=record
    repeat={kind:[r for r in records.values() if r['nonce'].startswith('repeat'+kind)] for kind in ('ip','owner')}
    summary={'version':1,'sessions':len(records),'repeat':{},'owner':{},'cost':[], 'cost_protocol':protocol,
             'stage_status':'BLOCKED','phase_complete':False}
    summary['session_quality'] = {sid: assess(record) for sid, record in records.items()}
    for kind,values in repeat.items():
        passed=len(values)==100 and all(r['state']=='IDLE' and assess(r)['status']=='PASS' for r in values)
        summary['repeat'][kind]={'count':len(values),'status':'PASS' if passed else 'BLOCKED',
            'independent_collector':all((r['inventory']['ip_perf_cpus']==0)==(kind!='ip') for r in values)}
    for nonce in ('functionalowner','fixtureprivate','fixturereuse','fixturepreempt'):
        found=[r for r in records.values() if r['nonce']==nonce]
        if not found:continue
        r=found[0]
        raw=files.get('/tmp/session-evidence/records/'+r['session_id']+'.jsonl','')
        events=[]
        for line in raw.splitlines():
            if line.startswith('{"version":'):
                try:events.append(json.loads(line))
                except ValueError:events.append({'kind':'sample_schema_error'})
        result=owner_report.analyze(events)
        edges=result['edges'];cross=[e for e in edges if e['relation']=='cross_container']
        summary['owner'][nonce]={'edges':len(edges),'cross_container_edges':len(cross),
             'loss':result['loss_or_recursion_gap'],'incomplete':result['incomplete_intervals'],
             'holder_offcpu_intervals':sum(len(e['holder_offcpu']) for e in edges),
             'holder_preemptions':sum(s['reason']=='preempted' for e in edges for s in e['holder_offcpu']),
             'private_zero_cross':not cross if nonce=='fixtureprivate' else None,
             'scope':'fixture and protocol coverage, not universal attribution or causal proof'}
    data={}
    for name,body in files.items():
        match=re.search(r'cost-(throughput|latency)-(\d+)-(off|idle|ip|owner)-(\d)\.log$',name)
        if not match:continue
        workload,round_id,mode,role=match.groups()
        prefix='CIS_RESULT ' if workload=='throughput' else 'CIS_LATENCY '
        rows=[numbers(line) for line in body.splitlines() if line.startswith(prefix)]
        if len(rows)==1:data[(workload,int(round_id),mode,int(role))]=rows[0]
    for workload in ('throughput','latency'):
        for mode in ('idle','ip','owner'):
            for role in range(2):
                changes=[];raw=[]
                for rnd in range(5):
                    base=data.get((workload,rnd,'off',role));trial=data.get((workload,rnd,mode,role))
                    if not base or not trial:continue
                    if workload=='throughput':
                        b=base['operations']/(base['end_ns']-base['start_ns']);v=trial['operations']/(trial['end_ns']-trial['start_ns'])
                        changes.append((1-v/b)*100)
                    else:changes.append((trial['p99_ns']/base['p99_ns']-1)*100)
                    raw.append({'round':rnd,'off':base,'trial':trial})
                ci=interval(changes)
                threshold=(1 if mode=='idle' else 3) if workload=='throughput' else 2 if mode=='idle' else protocol.get('diagnostic_window_p99_target_pct')
                passed=threshold is not None and ci.get('upper95_pct',float('inf'))<=threshold
                failed=threshold is not None and ci.get('lower95_pct',float('-inf'))>threshold
                quality = capture_quality(records, workload, mode) if mode != 'idle' else None
                status = 'PASS' if passed else 'FAIL' if failed else 'BLOCKED'
                if quality and quality['status'] != 'PASS': status = quality['status']
                summary['cost'].append(dict(workload=workload,mode=mode,role=role,threshold_pct=threshold,
                    status=status, capture_quality=quality, interval=ci,raw=raw))
    good=[r for r in records.values() if r.get('receipt') and r['receipt'].get('prepare_cpu_ns')]
    if good:
        summary['measured']={'prepare_cpu_ms_mean':statistics.mean(r['receipt']['prepare_cpu_ns']/1e6 for r in good),
            'capture_cpu_ms_max':max(r['receipt']['armed_capture_cpu_ns']/1e6 for r in good),
            'combined_rss_peak_mib':max(r.get('combined_rss_peak_bytes',0) for r in good)/2**20,
            'stop_lag_ms_max':max((r['receipt']['producers_stopped_ns']-r['receipt']['end_ns'])/1e6 for r in good if r['receipt']['end_ns']),
            'total_memory_complete':False,'kernel_background_attribution_complete':False}
    summary['gaps']=['all-inclusive kernel/background CPU and memory attribution',
                     'every allocation-step failure injection and disk-full control-channel tests',
                     'target lifecycle/migration and all capture-boundary runtime cases',
                     'combined CPU budget enforcement (not worker-only)',
                     'fixed cost thresholds and full fault matrix must all pass before P1 exit']
    summary['vm_exit_zero']='CIS_PROFILE_VM_EXIT=0' in text
    return summary


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('log');args=parser.parse_args()
    print(json.dumps(analyze(Path(args.log).read_text(errors='replace')),indent=2))
