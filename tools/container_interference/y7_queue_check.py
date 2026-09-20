# SPDX-License-Identifier: GPL-2.0
"""Request/response truth parser for the pending Y7 independent-socket cohort."""
from owner_report import fields

def workload(client,server,actor):
    c=[fields(l.split(' ',1)[1]) for l in client.splitlines() if l.startswith('Y7_QUEUE_CLIENT ')]
    s=[fields(l.split(' ',1)[1]) for l in server.splitlines() if l.startswith('Y7_QUEUE_SERVER ')]
    samples=[l.split(' ',1)[1] for l in client.splitlines() if l.startswith('Y7_QUEUE_LATENCIES ')]
    if len(c)!=1 or len(s)!=1 or len(samples)!=1: raise ValueError('both endpoint terminals required')
    c,s=c[0],s[0];v=[int(n) for n in samples[0].split(',')]
    if (set(c)!=set('actor due begin end offered completed errors timeouts period timeout p99 max sum'.split()) or
            set(s)!=set('actor received errors duplicates'.split()) or c['actor']!=actor or s['actor']!=actor or
            c['offered']!=4500 or c['completed']!=4500 or s['received']!=4500 or
            c['errors'] or s['errors'] or s['duplicates'] or c['period']!=2_000_000 or c['timeout']!=100_000_000 or
            not c['due']<=c['begin']<c['end'] or len(v)!=4500 or v!=sorted(v) or min(v)<0 or
            c['p99']!=v[4454] or c['max']!=v[-1] or c['sum']!=sum(v) or
            c['timeouts']!=sum(n>c['timeout'] for n in v)):
        raise ValueError('queue payload, delivery or arrival-relative timing failed')
    return dict(c,server=s,throughput=4500e9/(c['end']-c['due']),
        timing='scheduled arrival through validated echo; serialization backlog included',
        population='fixed offered sequence, not saturated throughput')
