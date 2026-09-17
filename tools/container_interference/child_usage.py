# SPDX-License-Identifier: GPL-2.0
"""Serialize child reaping with CPU snapshots, never with a blocking wait."""
import resource
import subprocess
import threading
import time


def reaped_cpu_ns():
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return round((usage.ru_utime + usage.ru_stime) * 1e9)


def live_cpu_ns(pid):
    # Fixed Linux ABI: include/linux/posix-timers.h make_process_cpuclock(),
    # CPUCLOCK_SCHED=2. This samples the whole process, not only its main TID.
    # Fail closed if unavailable; do not silently fall back to tick rounding.
    return time.clock_gettime_ns((~pid << 3) | 2)


class ChildProcesses:
    """All collector/helper spawn and reap operations must use this registry.

    A child transfers from its live CPU clock to RUSAGE_CHILDREN at waitpid(), not
    simply at exit. The transfer and snapshot must share a lock to avoid a
    missing or double-counted interval. This is a controller-local lock only.
    """
    def __init__(self):
        self.lock = threading.Lock()
        self.children = {}

    def spawn(self, *args, **kwargs):
        with self.lock:
            child = subprocess.Popen(*args, **kwargs)
            self.children[child.pid] = child
            return child

    def _poll(self, child):
        code = child.poll()
        if code is not None:
            self.children.pop(child.pid, None)
        return code

    def poll(self, child):
        with self.lock:
            return self._poll(child)

    def kill(self, child):
        with self.lock:
            child.kill()
            self._poll(child)

    def wait(self, child, timeout=None):
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            code = self.poll(child)
            if code is not None:
                return code
            if deadline is not None and time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(child.args, timeout)
            time.sleep(.01)

    def cpu_ns(self):
        with self.lock:
            for child in list(self.children.values()):
                self._poll(child)
            live = sum(live_cpu_ns(pid) for pid in self.children)
            return time.process_time_ns() + reaped_cpu_ns() + live

    def pids(self):
        with self.lock:
            return list(self.children)
