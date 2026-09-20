# SPDX-License-Identifier: GPL-2.0
"""Admission policy, not evidence that a configured backend is contended."""
from periodic_plan import digest

SCHEMA = 'cis-public-resource-policy-v2'
DEFAULT = frozenset(('ip', 'sched', 'reclaim', 'counter', 'alloc_backend', 'slub', 'page_backend', 'block'))
EXTENSIONS = frozenset(('owner', 'fd', 'sync', 'rwsem', 'allocator', 'net'))


def policy(extensions=()):
    if (not isinstance(extensions, (list, tuple)) or
            any(not isinstance(x, str) or x not in EXTENSIONS for x in extensions) or
            len(set(extensions)) != len(extensions)):
        raise ValueError('explicit distinct legacy collector names required')
    return dict(schema=SCHEMA, default=sorted(DEFAULT), extensions=sorted(extensions),
                automatic=sorted(DEFAULT - {'ip'}),
                sharing='candidate only; actual object and interval evidence required')


def validate(value):
    if not isinstance(value, dict) or value != policy(value.get('extensions', ())):
        raise ValueError('public resource policy mismatch')
    return value


def admit(value, collector, automatic=False):
    validate(value)
    allowed = set(value['automatic'] if automatic else value['default'] + value['extensions'])
    if collector not in allowed:
        raise PermissionError('collector is outside the public-resource profile; explicit extension required')


def fingerprint(value):
    return digest(validate(value))
