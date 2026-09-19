# SPDX-License-Identifier: GPL-2.0
"""Replay independent TCP and direct-I/O truth in the same four-container window."""
import argparse
import hashlib
import json
import re
from pathlib import Path

from block_fixture_check import check_case as block_check
from net_fixture_check import check_case as net_check
from net_source_audit import delta as net_delta
from joint_costs import analyze as costs
from joint_vm_check import workload
from prototype_admission import SOURCE_KEYS
from session_check import extract
from source_switches import validate
from unified_report import analyze
from net_report import analyze as net_report
from block_report import analyze as block_report

PLAN = dict(schema='cis-x7-mixed-v1', cases=['shared','private'], modes=['off','ip','net','block'],
    rounds=3, registered_roots=4, network_by_round=[[0,1],[2,3],[0,3]],
    ordinary_cpus=[0,0,1,1], ordinary_workloads=['file','file','vma','vma'],
    offered_per_actor=1500, period_ns=2_000_000, timeout_ns=100_000_000,
    fixture_cpus=[0,1], management_cpu=7, window_ms=2000, net_shift=0,
    block_offset_ns=10_000_000, memory_max_bytes=64<<20,
    devices=['/dev/vda','/dev/vdb'], device_bytes=16<<20, direct=True,
    scope='simultaneous bounded native TCP logical locks and direct I/O with ordinary file/VMA work',
    off='same-kernel idle controller, same business and fixture operations without attached probes',
    p99='record_only', throughput='fixed offered load, not saturation throughput')


def order():
    return [[case,r,mode] for case in PLAN['cases'] for r in range(3)
            for mode in (PLAN['modes'] if r%2==0 else list(reversed(PLAN['modes'])))]


def roles(r):
    network=PLAN['network_by_round'][r]
    return network, [i for i in range(4) if i not in network]


def selected(r,mode):
    network,block=roles(r)
    return network if mode=='net' else block if mode=='block' else [network[0],block[0]]


def overlap(net_truth, block_logs):
    """Require actual native operation overlap, not merely process existence."""
    count=0
    for log in block_logs:
        rows=re.findall(r'CIS_BLOCK_IO role=(\d+) iteration=(\d+) op=(read|write) offset=(\d+) before_ns=(\d+) after_ns=(\d+) bytes=(-?\d+) verified=(\d+)',log)
        if len(rows)!=8: raise ValueError('mixed block population')
        for _,iteration,_,_,lo,hi,_,_ in rows:
            holder=net_truth[0][int(iteration)]
            if not max(int(lo),holder['acquired_ns'])<min(int(hi),holder['release_begin_ns']):
                raise ValueError('network/block native operations did not overlap')
            count+=1
    return count


def verify_state(ev, ordinary, net_logs, block_logs, record, capture, hz):
    case,r,mode=ev['case'],ev['round'],ev['mode']
    if [case,r,mode] not in order(): raise ValueError('unknown mixed state')
    label='%s-%s%d'%(case,mode,r)
    network,block=roles(r)
    if (ev['label']!=label or len(set(ev['registered']))!=4 or ev['network_roots']!=network or
            ev['block_roots']!=block or ev['targets']!=[ev['registered'][i] for i in selected(r,mode)] or
            ev['ordinary_exit_codes']!=[0]*4 or ev['fixture_exit_codes']!=[0]*4):
        raise ValueError('mixed role, population or exit mismatch')
    if len(ordinary)!=4 or len(net_logs)!=2 or len(block_logs)!=2: raise ValueError('mixed log population')
    work=[workload(v) for v in ordinary]
    for i,row in enumerate(work):
        if row['mode']!=PLAN['ordinary_workloads'][i] or row['due_start_ns']!=ev['start_ns'] or row['timeouts']:
            raise ValueError('ordinary correctness or binding')
    window=ev['window']
    if not ev['start_ns']<window['start_ns']<window['end_ns']<min(w['end_ns'] for w in work):
        raise ValueError('ordinary work does not cover window')
    if not ev['before']['read_end_ns']<ev['start_ns']<max(w['end_ns'] for w in work)<ev['after']['time_ns']:
        raise ValueError('mixed cost boundaries')
    report=None; identities=None; cost=None
    if mode=='off':
        if record is not None or capture is not None or ev['session_id'] is not None: raise ValueError('OFF capture')
        validate(ev['active_sources'],None,0,2**64-1)
        validate(ev['idle_sources'],None,0,2**64-1)
    else:
        if (str(record['session_id'])!=str(ev['session_id']) or record['collector']!=mode or record['nonce']!=label.replace('-','') or
                record['targets']!=ev['targets'] or record['window']!=window or not record['objects_absent']):
            raise ValueError('mixed session binding or cleanup')
        report=analyze(record,capture)
        if report['quality']['status']!='PASS' or report['scope_audit'].get('status','PASS')!='PASS':
            raise ValueError('mixed capture quality')
        validate(ev['active_sources'],mode,record['receipt']['prepared_ns'],window['end_ns'])
        validate(ev['idle_sources'],None,window['end_ns'],2**64-1)
        if not ev['before']['read_end_ns']<record['requested_ns']<=record['receipt']['prepared_ns']<record['receipt']['destroyed_ns']<ev['after']['time_ns']:
            raise ValueError('mixed producer outside cost boundaries')
        identities=[record['root_identities'][key] for key in ev['targets']]
        cost=dict(process_cpu=record.get('process_cpu_budget'),rss_bytes=record.get('combined_rss_peak_bytes'),
                  controller_cpu_ns=record.get('controller_cpu_ns'),reaped_children_cpu_ns=record.get('reaped_children_cpu_ns'))
    net=net_report(record,capture) if mode=='net' else None
    blk=block_report(record,capture) if mode=='block' else None
    nt=net_check(case,window,net_logs,net,identities if net is not None else None)
    bt=block_check(case,window,block_logs,blk,identities if blk is not None else None,verify_blkcg=True)
    if nt['status']!='PASS' or bt['status']!='PASS': raise ValueError(('mixed independent truth',nt['errors'],bt['errors']))
    if net is not None:
        keys={(r['cookie'],r['socket']) for group in nt['truth'] for r in group}
        if any((s['cookie'],s['socket_address']) not in keys for s in net['sockets']):
            raise ValueError('unrelated socket attribution')
    overlap_count=overlap(nt['truth'],block_logs)
    audit=net_delta(*[dict(time_ns=ev[k]['time_ns'],source_audit=ev[k]['net_source_audit']) for k in ('before','after')])
    if mode!='net' and any(audit['totals'].values()): raise ValueError('network source active outside NET')
    if mode=='net' and (not audit['totals']['selected'] or audit['totals']['skipped']): raise ValueError('network source incomplete')
    return dict(label=label,case=case,round=r,mode=mode,workload=work,network=nt,block=bt,
        overlapping_operations=overlap_count,cost=cost,system_cost=costs(ev['before'],ev['after'],hz),
        network_source_audit=audit,relations=report['relations'] if report else [])


def comparisons(states):
    result=[]
    for state in states:
        if state['mode']=='off': continue
        matches=[s for s in states if s['mode']=='off' and (s['case'],s['round'])==(state['case'],state['round'])]
        if len(matches)!=1: raise ValueError('one paired OFF required')
        for actor,(a,b) in enumerate(zip(matches[0]['workload'],state['workload'])):
            result.append(dict(case=state['case'],round=state['round'],mode=state['mode'],actor=actor,
                role='target' if actor in selected(state['round'],state['mode']) else 'bystander',
                p99_change_ns=b['p99_ns']-a['p99_ns'],
                throughput_change_fraction=b['throughput_per_second']/a['throughput_per_second']-1,
                timeouts_before=a['timeouts'],timeouts_after=b['timeouts']))
    return result


def verify(serial,output):
    if serial.stat().st_size>128<<20: raise ValueError('serial capacity')
    raw=serial.read_bytes(); text=raw.decode(); files=extract(text); prefix='/tmp/mixed-evidence/'
    def value(name): return json.JSONDecoder().raw_decode(files[prefix+name].lstrip())[0]
    plan,declared,permit=[value(k+'.json') for k in ('plan','result','permit')]
    if plan['design']!=PLAN or plan['order']!=order(): raise ValueError('mixed frozen plan changed')
    if declared['source']!=plan['source'] or any(plan['source'][k]!=permit['source'][k] for k in SOURCE_KEYS):
        raise ValueError('mixed source binding')
    output.mkdir(mode=0o700); errors=[]; states=[]
    if not {'CIS_PROFILE_VM_EXIT=0','CIS_NET_FIXTURE_UNLOAD=0','CIS_BLOCK_DEVICE_UNLOAD=0'}<=set(text.splitlines()): errors.append('guest_exit_or_unload')
    if any(v in text for v in ('Oops:','Kernel panic','BUG: KASAN:','WARNING: CPU:')): errors.append('kernel_warning')
    expected=['%s-%s%d'%(case,mode,r) for case,r,mode in order()]
    if declared['labels']!=expected: errors.append('incomplete_population')
    for label in expected:
        ev=value(label+'-evidence.json'); record=None; capture=None
        if ev['label']!=label: raise ValueError('mixed evidence label changed')
        if ev['mode']!='off':
            sid=str(ev['session_id'])
            if not sid.isascii() or not sid.isdigit(): raise ValueError('mixed session id')
            record=value('records/'+sid+'.json')
            if any(record.get(k)!=plan['source'][k] for k in SOURCE_KEYS): raise ValueError('mixed record source')
            capture=(files[prefix+'records/'+sid+'.jsonl'].rstrip()+'\n').encode()
        try:
            states.append(verify_state(ev,[files[prefix+label+'-ordinary%d.log'%i] for i in range(4)],
                [files[prefix+label+'-net%d.log'%i] for i in range(2)],
                [files[prefix+label+'-block%d.log'%i] for i in range(2)],record,capture,plan['clock_ticks']))
        except (ValueError,KeyError,TypeError) as error:
            errors.append(label+': '+str(error))
    result=dict(schema='cis-x7-mixed-verification-v1',status='FAIL' if errors else 'PASS_SCOPED',errors=errors,
        states=states,comparisons=comparisons(states) if len(states)==len(expected) else [],
        serial_sha256=hashlib.sha256(raw).hexdigest(),source=plan['source'],x7_complete=False,
        limits=['bounded logical TCP fixture, not arbitrary protocol locks',
                'direct I/O requester/device evidence does not identify a unique blocker',
                'one collector per window, not concurrent producer acceptance',
                'bookend CPU/memory includes business and unrelated background',
                'fixed offered load and record-only P99, not performance certification'])
    (output/'verification.json').write_text(json.dumps(result,indent=2)); return result


if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('serial',type=Path); p.add_argument('output',type=Path)
    a=p.parse_args(); result=verify(a.serial,a.output)
    print(json.dumps(dict(status=result['status'],errors=result['errors'],states=len(result['states']))))
    raise SystemExit(result['status']=='FAIL')
