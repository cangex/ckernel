# SPDX-License-Identifier: GPL-2.0
"""Conservative process CPU stop policy; not accounting for all kernel work."""
from periodic_plan import DEFAULTS


class ProcessBudget:
    def __init__(self, cpu_ns, window_ms, plan=None):
        self.plan = dict(DEFAULTS, **(plan or {}))
        self.begin = cpu_ns
        self.phase_begin = cpu_ns
        self.phase = 'PREPARE'
        self.window_ms = window_ms
        self.peak_cpu_ns = 0
        self.violation = None
        self.phase_peaks = dict(PREPARE=0, CAPTURING=0, DRAIN=0)
        self.first_violation = None

    def limits(self):
        return dict(PREPARE=self.plan['prepare_cpu_ms'] * 1_000_000,
                    CAPTURING=self.window_ms * 20_000,
                    DRAIN=self.plan['drain_cpu_ms'] * 1_000_000)

    def snapshot(self):
        return dict(phase_peak_cpu_ns=dict(self.phase_peaks), phase_limits_ns=self.limits(),
                    total_peak_cpu_ns=self.peak_cpu_ns,
                    total_limit_ns=self.plan['process_cpu_ms'] * 1_000_000,
                    violation=self.violation, first_violation=self.first_violation,
                    boundary='controller-observed worker transitions; cooperative, not hard realtime')

    def check(self, cpu_ns, state):
        # Retain the high watermark across counters with different resolutions.
        self.peak_cpu_ns = max(self.peak_cpu_ns, cpu_ns-self.begin)
        phase = ('PREPARE' if state in ('PREPARE', 'ARMED') else
                 'CAPTURING' if state == 'CAPTURING' else 'DRAIN')
        reason = None
        if self.peak_cpu_ns > self.plan['process_cpu_ms'] * 1_000_000:
            reason = 'COMBINED_PROCESS_CPU_TOTAL'
        used = max(0, cpu_ns-self.phase_begin)
        self.phase_peaks[self.phase] = max(self.phase_peaks[self.phase], used)
        limit = self.limits()[self.phase]
        if used > limit:
            reason = reason or 'COMBINED_PROCESS_CPU_' + self.phase
        if reason and self.first_violation is None:
            self.first_violation = dict(reason=reason, phase=self.phase, phase_cpu_ns=used,
                                        phase_limit_ns=limit, total_cpu_ns=self.peak_cpu_ns)
        if phase != self.phase:
            self.phase, self.phase_begin = phase, cpu_ns
        self.violation = self.violation or reason
        return self.violation
