# SPDX-License-Identifier: GPL-2.0
"""Assess the bounded X0-X7 contract, not universal coverage or P1 acceptance.

Input must be the independent checker results produced by coverage_matrix;
this module does not accept a log's declared PASS as evidence.
"""

STAGES={
    'X0': ('control',),
    'X1': ('sync','rwsem','fd','fd_relations','fd_guard'),
    'X2': ('counter',),
    'X3': ('allocator','maple_context','slub'),
    'X4': ('net','net_isolation','net_reuse','backlog','net_tx','net_tx_failure',
           'net_tx_admission','net_release','net_capacity','net_guard'),
    'X5': ('block','block_tag','block_merge','block_lifecycle','block_inflight',
           'writeback','writeback_inode'),
    'X6': ('routing',),
    'X7': ('joint','mixed','rwsem_joint'),
}

COLLECTORS=('ip','owner','fd','slub','sched','reclaim','sync','counter','allocator','net','block','rwsem')
CONTROLS={*(('selective_load_'+c) for c in COLLECTORS),
          *(('worker_kill_'+c) for c in COLLECTORS),
          'pause_drain_and_shared_manual_budget','restart_paused_nonce_and_budget_preserved',
          'unregister_removes_future_target','real_missed_slots_not_replayed',
          'failed_verification_blocks_admission','stopped_worker_faulted_then_verified',
          'stopped_controller_worker_deadline','controller_crash_faulted_then_verified',
          'both_crash_faulted_then_verified','real_permit_expiry'}


def assess(evidence):
    passed=[e for e in evidence if e.get('status')=='PASS_SCOPED']
    observed={e['capability'] for e in passed}
    stages={name:dict(status='PASS_SCOPED',missing=[k for k in keys if k not in observed],
                     evidence=[e['name'] for e in passed if e['capability'] in keys])
            for name,keys in STAGES.items()}
    controls={r['name'] for e in passed if e['capability']=='control'
              for r in e['checked'].get('checks',[]) if r.get('status')=='PASS'}
    stages['X0']['missing']+=['control:'+name for name in sorted(CONTROLS-controls)]
    routing=[e for e in passed if e['capability']=='routing' and
             e['checked'].get('records')==10 and e['checked'].get('automatic')==2 and
             e['checked'].get('manual')==1 and len(e['checked'].get('discovery_timing',[]))==2 and
             len(e['checked'].get('reports',{}))==10 and all(
                 r.get('timing',{}).get('explanation_boundary')=='unified_analysis_complete_before_serialization' and
                 r['timing'].get('same_clock_as_capture') is True and
                 isinstance(r['timing'].get('explanation_lag_ns'),int) and r['timing']['explanation_lag_ns']>=0
                 for r in e['checked']['reports'].values())]
    if not routing: stages['X6']['missing'].append('same_boot_full_explanation_and_three_timing_boundaries')
    # Require common, SLUB, rwsem and mixed application regressions on the
    # same built kernel as the final live routing run.  Historical per-resource
    # truth remains individually pinned; it is not re-labelled as a fresh run.
    images=[]
    for route in routing:
        notes=route['checked'].get('source',{}).get('kernel_notes_sha256')
        if not notes: continue
        cohort=[e for e in passed if e['checked'].get('source',{}).get('kernel_notes_sha256')==notes]
        common=any(e['capability']=='joint' and len(e['checked'].get('states',[]))==33 for e in cohort)
        slub=any(e['capability']=='joint' and len(e['checked'].get('states',[]))==6 and
                 {s.get('mode') for s in e['checked']['states']}=={'off','slub'} for e in cohort)
        rwsem=any(e['capability']=='rwsem_joint' and len(e['checked'].get('states',[]))==60 for e in cohort)
        mixed=any(e['capability']=='mixed' and len(e['checked'].get('states',[]))==24 for e in cohort)
        current_controls={r['name'] for e in cohort if e['capability']=='control'
                          for r in e['checked'].get('checks',[]) if r.get('status')=='PASS'}
        # Expiry is a 20-minute controller-policy test, not a kernel data path.
        control=CONTROLS-{'real_permit_expiry'} <= current_controls
        if common and slub and rwsem and mixed and control: images.append(notes)
    if not images: stages['X7']['missing'].append('same_kernel_common_slub_rwsem_mixed_control_and_live_routing')
    failures=[e['name'] for e in evidence if e.get('status')!='PASS_SCOPED']
    for stage in stages.values():
        if stage['missing']: stage['status']='INCOMPLETE'
    complete=not failures and all(s['status']=='PASS_SCOPED' for s in stages.values())
    return dict(schema='cis-x-prototype-contract-v1',status='PASS_SCOPED' if complete else 'INCOMPLETE',
        x7_complete=complete,scope='bounded_X0_X7_prototype_only',stages=stages,failed_evidence=failures,
        joint_kernel_notes_sha256=sorted(set(images)),full_linux_coverage=False,production_accepted=False,
        limits=['historical resource truth remains bound to its own source and fixed selection',
                'guard cohorts validate rejection and cleanup, not valid dense attribution',
                'complete callback/background CPU and kernel memory remain unknown',
                'hardware cacheline causality, all locks, transformed skb ownership and device-internal blockers not certified',
                'P99 record-only; no bare-metal NUMA, saturated-throughput or production cost certification'])
