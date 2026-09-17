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

    def check(self, cpu_ns, state):
        # Sampling can race wait/reap. A high watermark avoids losing charged CPU.
        self.peak_cpu_ns = max(self.peak_cpu_ns, cpu_ns-self.begin)
        phase = ('PREPARE' if state in ('PREPARE', 'ARMED') else
                 'CAPTURING' if state == 'CAPTURING' else 'DRAIN')
        reason = None
        if self.peak_cpu_ns > self.plan['process_cpu_ms'] * 1_000_000:
            reason = 'COMBINED_PROCESS_CPU_TOTAL'
        limit = (self.plan['prepare_cpu_ms'] if self.phase == 'PREPARE' else
                 self.window_ms*20/1000 if self.phase == 'CAPTURING' else
                 self.plan['drain_cpu_ms']) * 1_000_000
        if cpu_ns-self.phase_begin > limit:
            reason = reason or 'COMBINED_PROCESS_CPU_' + self.phase
        if phase != self.phase:
            self.phase, self.phase_begin = phase, cpu_ns
        self.violation = self.violation or reason
        return self.violation
