# SPDX-License-Identifier: GPL-2.0
"""Interval clock alignment. Never assume symmetric transport delay."""
import math
import statistics


def align(samples, guest_ns, drift_ppm):
    if type(guest_ns) is not int or guest_ns < 0 or not isinstance(drift_ppm, (int,float)) or not math.isfinite(drift_ppm) or not 0 <= drift_ppm <= 10000:
        raise ValueError('explicit finite drift bound and guest time required')
    if len(samples) < 3:
        raise ValueError('at least three exchanges required')
    lows, highs, rtts = [], [], []
    last_seq = last_host = last_guest = -1
    for row in samples:
        seq, a, b, c, d = (row[k] for k in ('sequence','host_send_ns','guest_receive_ns','guest_send_ns','host_receive_ns'))
        if any(type(x) is not int or x < 0 for x in (seq,a,b,c,d)) or seq <= last_seq or a < last_host or b < last_guest or a > d or b > c:
            raise ValueError('clock exchange order invalid')
        last_seq, last_host, last_guest = seq, d, c
        # Offset is host_time - guest_time. The guest processing span is
        # excluded, but path asymmetry stays inside the causal bounds.
        lows.append(a-b-math.ceil(abs(guest_ns-b)*drift_ppm/1e6))
        highs.append(d-c+math.ceil(abs(guest_ns-c)*drift_ppm/1e6))
        rtts.append(d-a)
    low, high = max(lows), min(highs)
    if low > high:
        return dict(status='UNKNOWN', reason='clock/drift assumption inconsistent', host_interval_ns=None)
    inside = samples[0]['guest_receive_ns'] <= guest_ns <= samples[-1]['guest_send_ns']
    return dict(status='BOUNDED_CONDITIONAL' if inside else 'EXTRAPOLATED_CONDITIONAL',
                guest_ns=guest_ns, offset_interval_ns=[low,high], host_interval_ns=[guest_ns+low,guest_ns+high],
                uncertainty_width_ns=high-low, drift_assumption_ppm=drift_ppm,
                exchange_rtt_min_ns=min(rtts), exchange_rtt_median_ns=statistics.median(rtts),
                causal_attribution=False, limits='conditional on stated drift bound; finite transport interval is not an exact offset')


def sched_delta(before, after):
    if before.get('pid') != after.get('pid') or before.get('start_ticks') != after.get('start_ticks'):
        raise ValueError('QEMU task identity changed')
    if before['end_ns'] > after['begin_ns']:
        raise ValueError('unordered task reads')
    values = [b-a for a,b in zip(before['schedstat'],after['schedstat'])]
    if len(values)!=3 or any(x<0 for x in values):
        raise ValueError('schedstat reset or absent')
    return dict(runtime_ns=values[0], runnable_wait_ns=values[1], timeslices=values[2],
                encompassing_host_interval_ns=[before['begin_ns'],after['end_ns']],
                event_timing_known=False, limits='cumulative wait is not a per-request event or a holder attribution')
