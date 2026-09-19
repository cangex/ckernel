# SPDX-License-Identifier: GPL-2.0
"""Root-only source switch observations during an exclusive test session."""
from pathlib import Path
import time


def expected_fields(version, collector):
    if version not in ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10'):
        raise ValueError('unsupported source-switch version')
    v = int(version)
    if v < {'counter':2, 'allocator':3, 'net':5, 'block':6, 'rwsem':7, 'slub':8}.get(collector, 1):
        raise ValueError('unsupported source-switch version')
    result = dict(version=version, owner=str(int(collector=='owner')), fd=str(int(collector=='fd')))
    if v >= 2: result['counter'] = str(int(collector=='counter'))
    if v >= 3: result['allocator'] = str(int(collector=='allocator'))
    if v >= 4: result['allocator_release'] = str(int(collector=='allocator'))
    if v >= 5: result.update(net=str(int(collector=='net')),net_release=str(int(collector=='net')))
    if v >= 6:
        result.update({name:str(int(collector=='block')) for name in (
            'block_start','block_insert','block_issue','block_requeue','block_complete','block_merge','block_remap')})
    if v >= 7: result['rwsem'] = str(int(collector=='rwsem'))
    if v >= 8: result['slub'] = str(int(collector=='slub'))
    if v >= 9: result['block_tag'] = str(int(collector=='block'))
    if v >= 10: result['rwsem_filter'] = str(int(collector=='rwsem'))
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
