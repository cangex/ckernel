# SPDX-License-Identifier: GPL-2.0
"""Fail-closed semantic validation for new specialist relation records.

No adapter is enabled by declaring a model here. Existing owner-v2 readers are
kept intact; migration must preserve their original evidence and limitations.
"""
MODELS = ('holder_waiter', 'shared_updates', 'queue_service')
PHASES = ('queue', 'wait', 'acquire', 'service', 'complete', 'free')


def validate(record):
    if not isinstance(record, dict) or record.get('schema') != 'cis-relations-v3':
        raise ValueError('unsupported relation protocol')
    required = {'schema', 'model', 'evidence', 'session_epoch', 'object', 'participants',
                'intervals', 'unknown', 'causal_validation'}
    if set(record) != required or record['model'] not in MODELS or record['evidence'] not in ('E0', 'E1', 'E2', 'E3'):
        raise ValueError('unknown relation field or kind')
    if not isinstance(record['session_epoch'], str) or not 1 <= len(record['session_epoch']) <= 128:
        raise ValueError('bounded session epoch required')
    obj = record['object']
    if (not isinstance(obj, dict) or set(obj) != {'kind', 'id', 'lifetime_epoch', 'lifetime_proof'}
            or any(not isinstance(obj[k], str) or not 1 <= len(obj[k]) <= 256 for k in ('kind', 'id'))
            or obj['lifetime_proof'] not in ('observed_create_free', 'pinned', 'trusted_interval', 'unknown')
            or (obj['lifetime_epoch'] is not None and
                (not isinstance(obj['lifetime_epoch'], str) or not 1 <= len(obj['lifetime_epoch']) <= 128))):
        raise ValueError('invalid object identity')
    if record['evidence'] in ('E2', 'E3') and (not obj['lifetime_epoch'] or obj['lifetime_proof'] == 'unknown'):
        raise ValueError('session epoch is not object lifecycle proof')
    parties = record['participants']
    roles = {'holder_waiter': {'holder', 'waiter'}, 'shared_updates': {'contributor'},
             'queue_service': {'submitter', 'executor', 'contributor'}}[record['model']]
    if not isinstance(parties, list) or len(parties) > 32:
        raise ValueError('participant capacity')
    for party in parties:
        if (not isinstance(party, dict) or set(party) != {'role', 'container_id', 'generation', 'task_id'}
                or party['role'] not in roles
                or any(party[k] is not None and (type(party[k]) is not int or party[k] <= 0)
                       for k in ('container_id', 'generation', 'task_id'))
                or (party['container_id'] is None) != (party['generation'] is None)):
            raise ValueError('invalid participant; contributor is not holder')
    if record['model'] == 'holder_waiter' and record['evidence'] in ('E2', 'E3'):
        if not all(any(p['role'] == role and p['container_id'] is not None and p['task_id'] is not None
                       for p in parties) for role in ('holder', 'waiter')):
            raise ValueError('known holder and waiter required')
    intervals = record['intervals']
    if not isinstance(intervals, list) or len(intervals) > 64:
        raise ValueError('interval capacity')
    for interval in intervals:
        if (not isinstance(interval, dict) or set(interval) != {'phase', 'start_ns', 'end_ns', 'metric', 'value'}
                or interval['phase'] not in PHASES or interval['metric'] not in ('wall_ns', 'on_cpu_ns', 'cycles')
                or any(type(interval[k]) is not int or interval[k] < 0 for k in ('start_ns', 'end_ns', 'value'))
                or interval['end_ns'] < interval['start_ns']):
            raise ValueError('invalid interval or measurement')
        if interval['metric'] == 'wall_ns' and interval['value'] != interval['end_ns'] - interval['start_ns']:
            raise ValueError('wall time mismatch')
        if interval['metric'] == 'on_cpu_ns' and interval['value'] > interval['end_ns'] - interval['start_ns']:
            raise ValueError('on-CPU time exceeds interval')
    if (not isinstance(record['unknown'], list) or len(record['unknown']) > 64
            or any(not isinstance(x, str) or len(x) > 256 for x in record['unknown'])):
        raise ValueError('bounded unknown reasons required')
    causal = record['causal_validation']
    if record['evidence'] == 'E3':
        if (not isinstance(causal, dict) or set(causal) != {'artifact_sha256', 'controlled_intervention'}
                or causal['controlled_intervention'] is not True
                or not isinstance(causal['artifact_sha256'], str) or len(causal['artifact_sha256']) != 64
                or any(x not in '0123456789abcdef' for x in causal['artifact_sha256'])):
            raise ValueError('E3 needs independently auditable controlled intervention')
    elif causal is not None:
        raise ValueError('causal validation without E3')
    return record
