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
        if any(s.startswith(('__mutex_lock','mutex_lock','lockref_')) for s in symbols):
            selected=('owner','supported mutex/lockref candidate, object owner not yet known')
        elif any('reclaim' in s or s.startswith('shrink_') for s in symbols):
            selected=('reclaim','reclaim hotspot, pressure producer not yet known')
        elif (rates.get('cpu_wait_usec_per_s') or 0)>10000:
            selected=('sched','CPU pressure candidate, not proof of another container holding a resource')
        if selected:
            proposals.append(dict(target=row['target'],collector=selected[0],reason=selected[1],
                                  source_session=report['session_id'],requires_confirmation=True,
                                  window_ms=2000,execution='existing shared session budget only'))
    return proposals[:2]
