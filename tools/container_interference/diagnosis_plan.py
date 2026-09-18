# SPDX-License-Identifier: GPL-2.0
"""Recommendations only: all execution still goes through session admission."""


def recommend(report):
    if report.get('quality',{}).get('status')!='PASS':
        return []
    proposals=[]
    for row in report.get('candidates',[]):
        if not row.get('valid'):
            continue
        symbols=[item.get('symbol','') for item in row.get('top_ip',[])]
        rates=row.get('rates',{})
        selected=None
        if any(s.startswith(('page_counter_','propagate_protected_usage')) for s in symbols):
            selected=('counter','counter update candidate; no lock holder or cache-line cause inferred')
        elif any(s.startswith(('alloc_fd','close_fd','put_files_struct','dup_fd','__fd_install')) for s in symbols):
            selected=('fd','FD-table path candidate; shared files_struct not yet established')
        elif any(s.startswith(('mt_alloc','mas_alloc','kmem_cache_','___slab_alloc','__slab_alloc','new_slab','get_partial')) for s in symbols):
            selected=('allocator','allocation stage candidate; boot-selected cache and sampled coverage required')
        elif any(s.startswith(('lock_sock','release_sock','__release_sock','tcp_','skb_','__kfree_skb','napi_consume_skb')) for s in symbols):
            selected=('net','network candidate; selected native socket cookie and queue evidence required')
        elif any(s.startswith(('blk_','__blk','submit_bio','bio_','io_schedule')) for s in symbols):
            selected=('block','I/O candidate; direct request episode coverage, not a unique device blocker')
        elif any(s.startswith(('__mutex_lock','mutex_lock','lockref_')) for s in symbols):
            selected=('owner','supported mutex/lockref candidate, object owner not yet known')
        elif any(s.startswith(('rwsem_','down_read','down_write','native_queued_spin','queued_spin','_raw_spin')) for s in symbols):
            selected=('sync','generic wait candidate; reader/holder set not inferred')
        elif any('reclaim' in s or s.startswith('shrink_') for s in symbols):
            selected=('reclaim','reclaim hotspot, pressure producer not yet known')
        elif (rates.get('cpu_wait_usec_per_s') or 0)>10000:
            selected=('sched','CPU pressure candidate, not proof of another container holding a resource')
        if selected:
            proposals.append(dict(target=row['target'],collector=selected[0],reason=selected[1],
                                  source_session=report['session_id'],requires_confirmation=True,
                                  source_end_ns=(report.get('window') or {}).get('end_ns'),
                                  source_epoch=report.get('survey_epoch'),
                                  automatic_eligible=bool(row.get('candidate')),
                                  window_ms=2000,execution='existing shared session budget only'))
    return proposals[:2]
