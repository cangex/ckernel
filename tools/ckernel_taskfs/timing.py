# SPDX-License-Identifier: GPL-2.0
"""Completion-event timing checks; sleeps cannot acknowledge business completion."""
ORDER = ('request', 'ready', 'business_start', 'business_end', 'detached')


def validate_times(times):
    values = [times[k] for k in ORDER]
    if any(type(v) is not int or v < 0 for v in values) or values != sorted(values):
        raise ValueError('invalid monotonic lifecycle boundaries')
    ack = times['completion_ack']
    if ack < times['business_end'] or times['cost_end'] < ack:
        raise ValueError('cost end precedes explicit completion ack')
    final = times['mapping_reclaimed']
    if final < times['detached']:
        raise ValueError('reclaim precedes detach')
    return dict(business_s=(times['business_end']-times['business_start'])/1e9,
        result_s=(times['detached']-times['request'])/1e9,
        turnover_s=(final-times['request'])/1e9,
        end_snapshot_lag_s=(times['cost_end']-times['business_end'])/1e9)
