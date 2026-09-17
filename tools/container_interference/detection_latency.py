#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Episode-level latency gates; misses remain in the denominator."""
import math


def binomial_tail(n, successes, probability):
    if not 0 <= successes <= n or not 0 < probability < 1:
        raise ValueError('invalid binomial parameters')
    terms = [math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1) +
             k * math.log(probability) + (n - k) * math.log1p(-probability)
             for k in range(successes, n + 1)]
    top = max(terms)
    return min(1.0, math.exp(top) * sum(math.exp(x - top) for x in terms))


def gate(delays_ns, deadline_ms, probability, alpha=0.05):
    if deadline_ms <= 0 or not 0 < probability < 1 or not 0 < alpha < 1:
        raise ValueError('invalid latency gate')
    for delay in delays_ns:
        if delay is not None and (type(delay) is not int or delay < 0):
            raise ValueError('delay must be a nonnegative integer or a miss')
    n = len(delays_ns)
    successes = sum(x is not None and x <= deadline_ms * 1000000 for x in delays_ns)
    p = binomial_tail(n, successes, probability) if n else None
    ordered = sorted(delays_ns, key=lambda x: math.inf if x is None else x)
    empirical = ordered[math.ceil(n * probability) - 1] if n else None
    return {'episodes': n, 'within_deadline': successes,
            'misses': sum(x is None for x in delays_ns),
            'deadline_ms': deadline_ms, 'required_probability': probability,
            'empirical_quantile_ns': empirical,
            'one_sided_binomial_p': p, 'alpha': alpha,
            'status': 'PASS' if n and p <= alpha else 'UNRESOLVED',
            'assumption': 'predeclared independent episodes; not event-level samples'}
