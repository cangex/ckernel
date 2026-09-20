# SPDX-License-Identifier: GPL-2.0
import argparse
import hashlib
import json
from pathlib import Path

from net_fixture_check import CASES,RIGHTS_CASES,ORIGIN_CASES,case_order,check_case
from net_report import analyze
from net_source_audit import delta
from prototype_admission import SOURCE_KEYS
from session_check import extract
from source_switches import validate
from net_tx_failure_check import CASES as TX_FAILURE_CASES
from net_tx_admission_check import CASES as TX_ADMISSION_CASES
from net_release_check import CASES as TX_RELEASE_CASES
from net_isolation_check import QUOTA_CONFIG,namespaces,quota as check_quota


def verify(serial,output):
    if serial.stat().st_size>128<<20: raise ValueError('serial capacity')
    raw=serial.read_bytes(); text=raw.decode(); files=extract(text); prefix='/tmp/net-evidence/'
    def value(name): return json.JSONDecoder().raw_decode(files[prefix+name].lstrip())[0]
    plan,declared,permit=[value(k+'.json') for k in ('plan','result','permit')]
    output.mkdir(mode=0o700); errors=[]; states=[]
    cases=tuple(plan.get('cases',[]))
    if cases not in (CASES,RIGHTS_CASES,ORIGIN_CASES,TX_FAILURE_CASES,TX_ADMISSION_CASES,TX_RELEASE_CASES,('backlog',),('capacity',),('private',),('reuse',)): raise ValueError('unsupported frozen case set')
    quota=cases==('private',)
    reuse=cases==('reuse',)
    if reuse!=(plan.get('socket_reuse_validation') is True): errors.append('socket_reuse_plan')
    if reuse and plan.get('operation_spacing_ms')!=40: errors.append('reuse_frozen_parameters')
    if quota!=(plan.get('private_quota_validation') is True): errors.append('quota_plan')
    if quota and (plan.get('namespace_validation') is not True or plan.get('cpu_max')!=QUOTA_CONFIG or
                  plan.get('quota_work_cpu_ns')!=80000000): errors.append('quota_frozen_parameters')
    if plan.get('namespace_validation') and cases not in (ORIGIN_CASES,('private',)): errors.append('namespace_plan')
    txfailure=cases==TX_FAILURE_CASES
    txadmission=cases==TX_ADMISSION_CASES
    txrelease=cases==TX_RELEASE_CASES
    if txrelease and (plan.get('send_bytes')!=128 or plan.get('tx_release_validation') is not True):
        errors.append('release_plan')
    if txadmission:
        if (value('tx-memory-original.json')!=value('tx-memory-restored.json') or
                value('tx-memory-seed.json').get('bytes')!=4<<20 or
                any(plan.get(k)!=v for k,v in dict(send_bytes=128,pressure_operations=16,recovery_operations=8,
                    operation_spacing_ms=10,tx_admission_validation=True,seed_bytes=4<<20).items())):
            errors.append('admission_plan_or_restoration')
    if txfailure:
        from allocator_failure_check import SETTINGS
        if (value('tx-failslab-original.json')!=value('tx-failslab-restored.json') or
                value('tx-failslab-active.json')!=dict(settings=SETTINGS,cache='1') or
                value('tx-failslab-original.json')['settings']['probability']!='0' or
                value('tx-failslab-original.json')['cache'] not in ('0','1') or
                plan.get('send_bytes')!=128 or plan.get('operation_spacing_ms')!=100 or
                plan.get('tx_failure_validation') is not True): errors.append('fault_plan_or_restoration')
        if value('tx-failslab-original.json')['cache']=='1':
            setting=value('tx-failslab-cache-config.json')
            if setting.get('aliases')!='0' or 'slub_debug=A,skbuff_fclone_cache' not in setting.get('command',[]):
                errors.append('unmerged_fault_cache_boot_configuration')
    if cases==('capacity',) and any(plan.get(k)!=v for k,v in dict(capacity_per_actor=40,watch_capacity=64,post_detach_operations=40).items()):
        errors.append('capacity_plan')
    if cases in (RIGHTS_CASES,ORIGIN_CASES) and plan.get('fd_transfer')!='real SCM_RIGHTS; rightsPrivate recipient creates a different TCP socket':
        errors.append('rights_plan')
    if (cases==ORIGIN_CASES)!=(plan.get('origin_validation') is True): errors.append('origin_plan')
    if cases==ORIGIN_CASES and (plan.get('origin_prepare_before_lock_ms')!=300 or
                               plan.get('lock_start_after_window_ms')!=500): errors.append('origin_barrier_plan')
    if 'excluded_protocols' in plan and plan['excluded_protocols']!=['raw_tcp','udp']:
        errors.append('protocol_negative_plan')
    if 'CIS_PROFILE_VM_EXIT=0' not in text.splitlines() or 'CIS_NET_FIXTURE_UNLOAD=0' not in text.splitlines():
        errors.append('guest_exit_or_unload')
    if any(s in text for s in ('BUG: KASAN:','Oops:','Kernel panic','WARNING: CPU:')): errors.append('kernel_warning')
    if (plan.get('order')!=case_order(cases) or plan.get('rounds')!=3 or
            plan.get('net_shift')!=0 or plan.get('hold_ms')!=30 or plan.get('operations')!=(1 if txrelease else 24 if txadmission else 8 if txfailure or reuse else 4)): errors.append('frozen_plan')
    if cases==('backlog',) and (plan.get('unheld_drain_transfers')!=1 or plan.get('drain_offset_ms')!=450 or
                              plan.get('skb_release_not_bounded_by_recv_return') is not True): errors.append('drain_plan')
    if any(declared['source'].get(k)!=permit['source'].get(k) for k in SOURCE_KEYS): errors.append('source_binding')
    for label in case_order(cases):
        ev=value(label+'-evidence.json'); logs=[files[prefix+label+'-%d.log'%i] for i in range(2)]
        report=None; identities=None
        if '-net' in label:
            sid=str(ev['session_id'])
            if not sid.isascii() or not sid.isdigit(): raise ValueError('session id')
            record=value('records/'+sid+'.json')
            if any(record.get(k)!=permit['source'].get(k) for k in SOURCE_KEYS): errors.append('session_source_'+label)
            capture=(files[prefix+'records/'+sid+'.jsonl'].rstrip()+'\n').encode()
            report=analyze(record,capture); identities=[record['root_identities'][key] for key in ev['targets']]
            if record['nonce']!=label.replace('-','') or record['window']!=ev['window'] or not record['objects_absent']:
                errors.append('session_boundary_'+label)
            validate(ev['active_sources'],'net',record['receipt']['prepared_ns'],record['window']['end_ns'])
            validate(ev['idle_sources'],None,record['window']['end_ns'],2**64-1)
            (output/(label+'-report.json')).write_text(json.dumps(report,indent=2))
        else:
            validate(ev['active_sources'],None,0,2**64-1); validate(ev['idle_sources'],None,0,2**64-1)
        if reuse:
            from net_reuse_check import check as check_reuse
            result=check_reuse(ev['window'],logs,report,identities)
        elif txrelease:
            from net_release_check import check as check_release
            result=check_release(label.split('-')[0],ev['window'],logs,report,identities)
        elif txadmission:
            from net_tx_admission_check import check as check_tx_admission
            if ev['memory_restored']['tcp_mem'].split()!=value('tx-memory-original.json')['tcp_mem'].split():
                errors.append('memory_restore_'+label)
            result=check_tx_admission(label.split('-')[0],ev['window'],logs,ev['memory_configuration'],
                                     ev['memory_restored'],report,identities)
        elif txfailure:
            from net_tx_failure_check import check as check_tx_failure
            result=check_tx_failure(label.split('-')[0],ev['window'],logs,report,identities)
        elif cases==('capacity',):
            from net_capacity_check import check as check_capacity
            result=check_capacity(ev['window'],logs,record if '-net' in label else None,
                capture if '-net' in label else None,ev['idle_sources'])
        else:
            result=check_case(label.split('-')[0],ev['window'],logs,report,identities,require_origin=cases==ORIGIN_CASES,
                              require_protocol_negative='excluded_protocols' in plan,
                              require_tx=plan.get('tx_allocation_validation') is True)
        if plan.get('namespace_validation'):
            result['namespace_validation']=namespaces(label.split('-')[0],logs,report)
            if quota: result['quota_validation']=check_quota(ev['window'],logs,ev['before'],ev['after'])
            for key in ('namespace_validation','quota_validation'):
                if key in result and result[key]['status']!='PASS':
                    result['errors'].extend(result[key]['errors']); result['status']='FAIL'
        source=delta(ev['source_before'],ev['source_after'])
        if cases==('capacity',) and any(delta(ev['post_detach_source_before'],ev['source_after'])['totals'].values()):
            errors.append('callbacks_after_detach_'+label)
        if '-off' in label and any(source['totals'].values()): errors.append('off_not_quiet_'+label)
        if '-net' in label and (not source['totals']['selected'] or source['totals']['skipped']): errors.append('source_gap_'+label)
        if result['status']!='PASS' or ev['exit_codes']!=[0,0]: errors.append(label)
        states.append(dict(label=label,result=result,source_audit=source))
    result=dict(status='FAIL' if errors else 'PASS',errors=errors,states=states,source=declared['source'],
        serial_sha256=hashlib.sha256(raw).hexdigest(),scope='native Socket close and address reuse negative' if reuse else 'CPU quota and namespace negative, not Socket lock positive' if quota else 'native original skb backend return and retained clone' if txrelease else 'native TCP memory admission rejection' if txadmission else
            'native TCP send backend failure and recovery' if txfailure else 'native TCP logical lock fixture only',
        x4_status='INCOMPLETE',performance_certification='NOT_ACCEPTED')
    (output/'verification.json').write_text(json.dumps(result,indent=2)); return result


if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('serial',type=Path); p.add_argument('output',type=Path)
    args=p.parse_args(); r=verify(args.serial,args.output)
    print(json.dumps(dict(status=r['status'],errors=r['errors'],states=len(r['states']))))
    raise SystemExit(r['status']!='PASS')
