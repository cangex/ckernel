# SPDX-License-Identifier: GPL-2.0
"""Pure monotonic-clock scheduler; never performs collection or filesystem IO."""
from collections import Counter, deque
import random

from periodic_plan import NS, capacity, validate_plan


class Schedule:
    def __init__(self, plan, clock):
        self.plan = validate_plan(plan)
        self.clock = clock
        self.random = random.Random(self.plan['seed'])
        self.roots = {}
        self.enabled = False
        self.next_ns = None
        self.last_admit_ns = None
        self.turn = 0
        self.skips = Counter()
        self.recent = deque(maxlen=64)

    def add(self, key):
        if key in self.roots:
            return
        if not capacity(self.plan, len(self.roots)+1)['capacity_admissible']:
            raise ValueError('requested coverage exceeds capacity')
        self.roots[key] = dict(joined_ns=self.clock(), served_ns=None, attempted_ns=None,
                               valid_ns=None, candidate=False, unavailable=False, failures=0)

    def remove(self, key):
        self.roots.pop(key, None)

    def enable(self):
        self.enabled = True
        self.next_ns = max(self.clock(), self.last_admit_ns or 0) + self.delay()

    def pause(self):
        self.enabled = False
        self.next_ns = None

    def delay(self):
        jitter = self.random.randint(0, self.plan['jitter_ms']) * 1_000_000
        return self.plan['interval_s'] * NS + jitter

    def timeout(self):
        if not self.enabled:
            return None
        return max(0, (self.next_ns-self.clock())/NS)

    def _age(self, key):
        item = self.roots[key]
        return (item['attempted_ns'] if item['attempted_ns'] is not None else item['joined_ns'], key)

    def poll(self, reason=None):
        now = self.clock()
        if not self.enabled or now < self.next_ns:
            return None
        planned = self.next_ns
        # Skip missed slots, never catch up; the actual start anchors the next slot.
        missed = (now-planned)//(self.plan['interval_s']*NS)
        self.skips['missed_slots'] += missed
        self.next_ns = now + self.delay()
        eligible = sorted((key for key, value in self.roots.items() if not value['unavailable']), key=self._age)
        if not reason and not eligible:
            reason = 'no_eligible_roots'
        if reason:
            self.skips[reason] += 1
            self.recent.append(dict(planned_ns=planned, actual_ns=now, reason=reason))
            return None
        chosen = eligible[:self.plan['targets_per_session']]
        self.turn += 1
        if len(chosen) == 2 and self.turn % 4 == 0:
            candidates = [key for key in eligible if key != chosen[0] and self.roots[key]['candidate']]
            if candidates:
                chosen[1] = candidates[0]
        return dict(targets=chosen, planned_ns=planned, actual_ns=now)

    def admit(self, targets, manual=False):
        now = self.clock()
        if self.last_admit_ns is not None and now-self.last_admit_ns < self.plan['interval_s']*NS:
            raise ValueError('host interval budget exhausted')
        self.last_admit_ns = now
        if self.enabled:
            self.next_ns = max(self.next_ns, now+self.delay())
        for key in targets:
            self.roots[key]['attempted_ns'] = now
        if manual:
            self.skips['manual_consumed_slot'] += 1

    def outcome(self, key, *, complete=False, valid=False, candidate=False, unavailable=False):
        if key not in self.roots:
            return
        item = self.roots[key]
        if complete:
            item['served_ns'] = self.clock()
        else:
            item['failures'] += 1
        if valid:
            item['valid_ns'] = self.clock()
        item['candidate'] = bool(candidate) if valid else False
        item['unavailable'] = unavailable

    def status(self):
        now = self.clock()
        entries = {}
        for key, value in self.roots.items():
            entries[key] = dict(value, sample_age_s=None if value['valid_ns'] is None
                                else (now-value['valid_ns'])/NS)
        return dict(enabled=self.enabled, next_ns=self.next_ns, last_admit_ns=self.last_admit_ns,
                    capacity=capacity(self.plan, len(entries)), roots=entries,
                    skipped=dict(self.skips), recent=list(self.recent))
