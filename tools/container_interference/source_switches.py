# SPDX-License-Identifier: GPL-2.0
"""Root-only source switch observations during an exclusive test session."""
from pathlib import Path
import time


def expected_fields(version, collector):
    if version not in ('1', '2') or version == '1' and collector == 'counter':
        raise ValueError('unsupported source-switch version')
    result = dict(version=version, owner=str(int(collector=='owner')), fd=str(int(collector=='fd')))
    if version == '2': result['counter'] = str(int(collector=='counter'))
    return result


def observe(collector=None):
    before=time.monotonic_ns()
    text=Path('/sys/kernel/debug/cis_sources').read_text()
    after=time.monotonic_ns()
    fields=dict(item.split('=',1) for item in text.split())
    expected=expected_fields(fields.get('version'), collector)
    if fields!=expected: raise ValueError(('source switch mismatch',fields,expected))
    return dict(before_ns=before,after_ns=after,expected_collector=collector,observed=fields)


def validate(observation,collector,lower_ns,upper_ns):
    expected=expected_fields(observation.get('observed',{}).get('version'), collector)
    if (observation.get('expected_collector')!=collector or observation.get('observed')!=expected or
            not lower_ns<=observation['before_ns']<=observation['after_ns']<=upper_ns):
        raise ValueError('source switches or observation boundary mismatch')
