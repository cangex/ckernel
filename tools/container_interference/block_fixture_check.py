# SPDX-License-Identifier: GPL-2.0
import re

CASES=('shared','private')


def case_order():
    return ['%s-%s-r%d'%(case,mode,round_) for round_ in range(1,4)
            for case in CASES for mode in (('off','block') if round_%2 else ('block','off'))]


def check_case(case,window,logs,report=None,identities=None):
    errors=[]; actors=[]; devices=[]; operations=[]; associated=[]
    for role,text in enumerate(logs):
        pids=re.findall(r'CIS_SESSION_CONTAINER host_pid=(\d+)',text)
        head=re.findall(r'CIS_BLOCK_BEGIN role=(\d+) major=(\d+) minor=(\d+) start_ns=(\d+)',text)
        rows=re.findall(r'CIS_BLOCK_IO role=(\d+) iteration=(\d+) op=(read|write) offset=(\d+) before_ns=(\d+) after_ns=(\d+) bytes=(-?\d+) verified=(\d+)',text)
        if len(pids)!=1 or len(head)!=1 or len(rows)!=8 or 'CIS_BLOCK_DONE operations=8 errors=0' not in text:
            errors.append('workload_protocol_%d'%role); continue
        actors.append(int(pids[0])); devices.append([int(head[0][1]),int(head[0][2])]); ops=[]
        if int(head[0][0])!=role: errors.append('role')
        for n,row in enumerate(rows):
            r,i,op,offset,lo,hi,size,verified=row; lo=int(lo); hi=int(hi)
            if (int(r)!=role or int(i)!=n//2 or op!=('write','read')[n%2] or int(offset)!=(1+role*8+n//2)*4096
                    or int(size)!=4096 or verified!='1' or not window['start_ns']<=lo<hi<=window['end_ns']):
                errors.append('operation_truth')
            ops.append(dict(interval_ns=[lo,hi],operation=0 if op=='read' else 1))
        operations.append(ops)
    if len(devices)==2 and ((devices[0]==devices[1])!=(case=='shared')): errors.append('device_case')
    if report is not None:
        if report['quality']['status']!='PASS' or report['scope_audit']['status']!='PASS': errors.append('capture_quality')
        for role,ops in enumerate(operations):
            identity=identities[role]
            for op in ops:
                lo,hi=op['interval_ns']
                matches=[r for r in report['requests'] if r['submitter'][:3]==[identity['id'],identity['generation'],actors[role]]
                    and lo<=r['episode_ns']<=hi]
                if (len(matches)!=1 or matches[0]['terminal']!='data_completion' or
                        matches[0]['episode_interval_ns'][1]>hi or matches[0]['devices']!=[devices[role]] or
                        matches[0]['operation']&255!=op['operation'] or matches[0]['initial_bytes']!=4096 or
                        sum(c['bytes'] for c in matches[0]['completions'])!=4096 or matches[0]['uncertainty']):
                    errors.append('request_call_pair_%d'%role)
                else: associated.append([matches[0]['request'],matches[0]['episode_ns']])
        if len(associated)!=len(report['requests']): errors.append('unexpected_request')
        if any(r['blocking_container'] is not None for r in report['requests']): errors.append('false_blocker')
    return dict(status='FAIL' if errors else 'PASS',errors=sorted(set(errors)),host_tasks=actors,devices=devices,
        successful_operations=sum(len(v) for v in operations),associated_episodes=associated,
        unique_blocking_container='NOT_ESTABLISHED',scope='direct I/O request lifecycle, not device saturation causality')
