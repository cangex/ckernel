# SPDX-License-Identifier: GPL-2.0
"""Root-only source switch observations during an exclusive test session."""
from pathlib import Path
import time


def observe(collector=None):
    before=time.monotonic_ns()
    text=Path('/sys/kernel/debug/cis_sources').read_text()
    after=time.monotonic_ns()
    fields=dict(item.split('=',1) for item in text.split())
    expected=dict(version='1',owner=str(int(collector=='owner')),fd=str(int(collector=='fd')))
    if fields!=expected: raise ValueError(('source switch mismatch',fields,expected))
    return dict(before_ns=before,after_ns=after,expected_collector=collector,observed=fields)


def validate(observation,collector,lower_ns,upper_ns):
    expected=dict(version='1',owner=str(int(collector=='owner')),fd=str(int(collector=='fd')))
    if (observation.get('expected_collector')!=collector or observation.get('observed')!=expected or
            not lower_ns<=observation['before_ns']<=observation['after_ns']<=upper_ns):
        raise ValueError('source switches or observation boundary mismatch')
