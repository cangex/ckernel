#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
import argparse
import hashlib
import json
from pathlib import Path
from session_check import extract
from owner_report import fields
from source_switches import expected_fields, validate

CHECKS=['strict_input_and_overflow','invalid_socket_fd','invalid_device_and_queue','exclusive',
        'immutable_selection','inherited_fd_not_authority','same_object_change_invalidates',
        'revoke_attached_noop_probe','same_handle_different_resource','replacement_invalidates']


def verify(serial,output):
    if serial.stat().st_size>16<<20: raise ValueError('serial capacity')
    raw=serial.read_bytes(); text=raw.decode(); files=extract(text)
    prefix='/tmp/y5-control-evidence/'
    def value(name): return json.JSONDecoder().raw_decode(files[prefix+name].lstrip())[0]
    record=value('result.json'); commands=value('commands.json'); errors=[]
    if ('CIS_PROFILE_VM_EXIT=0' not in text.splitlines() or
            'CIS_QUEUE_DEVICE_UNLOAD=0' not in text.splitlines()): errors.append('exit_or_unload')
    if any(s in text for s in ('BUG: KASAN:','Oops:','Kernel panic','WARNING: CPU:')): errors.append('kernel_warning')
    if record.get('checks')!=CHECKS: errors.append('control_population')
    rows=record['leases']
    if (len(rows)!=3 or any(r['valid']!=1 or not r['lease'] or not r['qdisc'] for r in rows) or
            [r['lease'] for r in rows]!=sorted({r['lease'] for r in rows}) or
            rows[0]['ifindex']!=rows[1]['ifindex'] or rows[1]['ifindex']==rows[2]['ifindex'] or
            rows[1]['qdisc']==rows[2]['qdisc'] or rows[1]['handle']!=rows[2]['handle']):
        errors.append('identity_or_generation')
    if record['changed']['valid'] or record['replaced']['valid']: errors.append('invalid_epoch_not_rejected')
    active={k:str(v) for k,v in fields(record['active']).items()}
    if active!=expected_fields('19','qdisc'): errors.append('private_sources_or_queue_state')
    revoked={k:str(v) for k,v in fields(record['revoked']).items()}
    wanted=expected_fields('19','qdisc'); wanted['qdisc_filter']='0'
    if revoked!=wanted: errors.append('revocation')
    validate(record['idle'],None,0,2**64-1)
    deleted=[r for r in commands if r['command'][1:3]==['link','del']]
    if (any(r['returncode'] for r in commands) or
            {r['command'][-1] for r in deleted}!={'cisy5a','cisy5b'}): errors.append('device_cleanup')
    result=dict(status='FAIL' if errors else 'PASS_CONTROL_ONLY',errors=errors,checks=CHECKS,
        serial_sha256=hashlib.sha256(raw).hexdigest(),record=record,
        scope='administrative lease correctness only; not Y5 traffic/coverage/performance acceptance')
    output.mkdir(mode=0o700); (output/'verification.json').write_text(json.dumps(result,indent=2))
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('serial',type=Path); p.add_argument('output',type=Path)
    a=p.parse_args(); r=verify(a.serial,a.output)
    print(json.dumps(dict(status=r['status'],errors=r['errors'])))
    raise SystemExit(r['status']!='PASS_CONTROL_ONLY')
