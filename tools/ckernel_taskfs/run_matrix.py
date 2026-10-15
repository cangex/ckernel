#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Finite correctness admission. Formal execution remains gated, not implied."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import time
from budget import GIB,MIB
from manifest import Store
from dm_backend import Backend
from lifecycle import Lifecycle
from identity import new_token
from go_adapter import execute,geometry,reference,phase_snapshot


def save(path,value):
    with path.open('x') as stream:json.dump(value,stream,indent=2)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('root');parser.add_argument('--admission-only',action='store_true')
    args=parser.parse_args()
    if not args.admission_only:parser.error('formal runner not admitted; explicit correctness-only mode required')
    os.umask(0o077);os.sched_setaffinity(0,{112,113,114,115})
    module,inputs=reference.load()
    root=Path(args.root).absolute();root.mkdir()
    store=Store(root/'pool',True,root.name);backend=Backend(store);life=Lifecycle(store,backend)
    plan=[(arm,run) for run,order in enumerate(('SGFB','BFSG','GBSF'),1) for arm in order]
    config=dict(data_bytes=24*GIB,metadata_bytes=128*MIB,chunk_sectors=128,
                max_branches=32,max_pending=4,root_floor=6*GIB)
    save(root/'plan.json',dict(scope='12 solo correctness admissions; NOT pilot/formal or VM recovery acceptance',
        plan=plan,geometry={arm:geometry(arm,24) for arm in 'SGFB'},pool=config,
        boot=store.data['boot'],kernel=backend.run(['uname','-r']),inputs=inputs,image=module.IMAGE,
        runner_sha256=reference.SOURCE_SHA,source_hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest()
            for p in Path(__file__).parent.glob('*.py')},official='unchanged frozen Go evaluator after all business ends',
        boundary='snapshot/format/mount in setup; scoring retention separate; end snapshot requires all done events'))
    summary=dict(status='FAIL',states=[],phase_before=phase_snapshot(),begin_ns=time.monotonic_ns())
    try:
        if backend.run(['docker','ps','-q']):raise RuntimeError('active containers')
        backend.prepare_pool(config)
        template=life.prepare_template(geometry('B',1)[0],new_token())
        summary['infrastructure_ready_ns']=time.monotonic_ns()
        for arm,run in plan:
            row=execute(module,store,backend,life,root,f'taskfs-{root.name}-{arm}-{run}',arm,1,template['id'])
            summary['states'].append(dict(condition=arm,run=run,status=row['status'],target_s=row['business']['target_s']))
            save(root/f'completed-{len(summary["states"]):02d}.json',summary['states'][-1])
        life.verify_template(template['id']);backend.destroy_pool()
        reference.freeze(module);summary['status']='PASS'
    except BaseException as exc:
        summary['error']=repr(exc);raise
    finally:
        summary.update(end_ns=time.monotonic_ns(),phase_after=phase_snapshot(),
            formal_status='NOT_RUN',net_benefit='NOT_ESTABLISHED',vm_faults='NOT_RUN')
        save(root/'summary.json',summary);store.close();print(json.dumps(summary))


if __name__=='__main__':main()
