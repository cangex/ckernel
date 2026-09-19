# SPDX-License-Identifier: GPL-2.0
"""Native merge transfers and bounded, issue-local bio byte provenance.

Neither the request submitter nor a bio's blkcg is a device blocking owner.
Snapshots on retries are alternatives, never added as new submitted bytes.
"""
from collections import Counter, defaultdict
import json

from owner_report import fields
from explain import within_window

COMMON = {'protocol', 'sample_time_ns', 'request', 'episode_ns'}
LINK = COMMON | {'queue', 'victim', 'victim_episode_ns', 'bio', 'merge_kind', 'before_bytes', 'added_bytes'}
BIO = COMMON | {'bio', 'index', 'bytes', 'remaining', 'more', 'bio_cgroup', 'bio_owner_id',
                'bio_owner_generation', 'bio_origin_overdepth'}


def analyze_provenance(record, raw, episodes):
    supported = 'block_link' in record.get('inventory', {}).get('program_names', [])
    errors = Counter(); links = []; snapshots = defaultdict(list)
    identities = dict(record.get('root_identities', {})); identities.update(record.get('owner_identities', {}))
    known = {(v['id'], v['generation']) for v in identities.values()}
    count = 0
    for line in raw.decode().splitlines():
        item = json.loads(line); kind = item.get('kind')
        if kind not in ('BLOCK_LINK', 'BLOCK_BIO'): continue
        count += 1
        if count > 16384: errors['provenance_capacity'] += 1; continue
        row = fields(item.get('detail', '')); required = LINK if kind == 'BLOCK_LINK' else BIO
        if (not supported or not required <= row.keys() or
                any(type(row[k]) is not int or row[k] < 0 for k in required) or row['protocol'] != 1 or
                not all(row[k] for k in ('request', 'episode_ns', 'bio'))):
            errors['provenance_schema'] += 1; continue
        key = (row['request'], row['episode_ns']); parent = episodes.get(key)
        if not parent or (item.get('id'), item.get('generation')) != (parent[0]['id'], parent[0]['generation']):
            errors['provenance_episode_identity'] += 1; continue
        if not within_window(record, row['episode_ns'], row['sample_time_ns']):
            errors['provenance_window'] += 1; continue
        if kind == 'BLOCK_LINK':
            if (row['merge_kind'] not in (1, 2, 3, 4) or not row['queue'] or
                    row['before_bytes'] + row['added_bytes'] > 0xffffffff or not row['added_bytes'] or
                    row['victim'] == row['request'] or
                    (row['merge_kind'] == 1) != bool(row['victim']) or
                    not row['victim'] and row['victim_episode_ns']):
                errors['merge_link_schema'] += 1; continue
            links.append(row)
        else:
            origin = (row['bio_owner_id'], row['bio_owner_generation'])
            if (row['index'] >= 8 or row['more'] not in (0, 1) or row['bio_origin_overdepth'] not in (0, 1) or
                    origin != (0, 0) and (origin not in known or row['bio_origin_overdepth']) or
                    row['bytes'] > row['remaining']):
                errors['bio_snapshot_schema'] += 1; continue
            snapshots[(key, row['sample_time_ns'])].append(row)
    result = []; transfers = []; linked_victims = set()
    for (key, now), rows in sorted(snapshots.items()):
        rows.sort(key=lambda r: r['index'])
        issue = [r for r in episodes[key] if r['phase'] == 3 and r['sample_time_ns'] == now]
        size = rows[0]['remaining']; captured = sum(r['bytes'] for r in rows)
        if (len(issue) != 1 or issue[0]['remaining'] != size or
                [r['index'] for r in rows] != list(range(len(rows))) or
                len({r['bio'] for r in rows}) != len(rows) or
                any(r['remaining'] != size for r in rows) or
                any(not r['more'] for r in rows[:-1]) or
                rows[-1]['more'] and len(rows) != 8 or captured > size or
                not rows[-1]['more'] and captured != size):
            errors['bio_snapshot_inconsistent'] += 1; continue
        weights = Counter(); unknown = size - captured
        for row in rows:
            owner = (row['bio_owner_id'], row['bio_owner_generation'])
            if all(owner): weights[owner] += row['bytes']
            else: unknown += row['bytes']
        result.append(dict(request=key[0], episode_ns=key[1], issue_ns=now, remaining_bytes=size,
            observed_bios=len(rows), truncated=bool(rows[-1]['more']), unknown_bytes=unknown,
            sources=[dict(container=list(owner), bytes=n, fraction=n/size if size else None)
                     for owner, n in sorted(weights.items())],
            source_semantics='bio_blkcg_at_issue_not_exclusive_owner', blocking_container=None))
    if supported:
        for key, rows in episodes.items():
            ledger = None; route_unknown = False
            merged = [r for r in links if (r['request'], r['episode_ns']) == key]
            events = [(r['sample_time_ns'], 0, r) for r in rows]
            events += [(r['sample_time_ns'], 1, r) for r in merged]
            if len({t for t, _, _ in events}) != len(events): errors['ambiguous_merge_order'] += 1
            for now, is_link, row in sorted(events, key=lambda r: (r[0], r[1])):
                if is_link:
                    if (ledger is None or row['queue'] != rows[0]['queue'] or
                            not route_unknown and ledger != row['before_bytes']):
                        errors['merge_byte_ledger'] += 1
                    ledger = row['before_bytes'] + row['added_bytes']
                    victim = (row['victim'], row['victim_episode_ns'])
                    state = 'UNOBSERVED_VICTIM_EPISODE' if row['victim'] else 'BIO_APPEND'
                    if row['victim_episode_ns']:
                        other = episodes.get(victim, [])
                        terminal = [r for r in other if r['phase'] == 6]
                        if (victim in linked_victims or not other or len(terminal) != 1 or
                                not other[0]['sample_time_ns'] <= now < terminal[0]['sample_time_ns'] or
                                terminal[0]['remaining'] != row['added_bytes'] or
                                terminal[0]['queue'] != row['queue'] or terminal[0]['bio'] != row['bio']):
                            errors['merge_victim_mismatch'] += 1
                        else:
                            linked_victims.add(victim); state = 'OBSERVED_TRANSFER'
                    transfers.append(dict(survivor=list(key), victim=list(victim) if row['victim'] else None,
                        time_ns=now, kind=row['merge_kind'], before_bytes=row['before_bytes'],
                        transferred_bytes=row['added_bytes'], state=state, blocking_container=None))
                    continue
                phase = row['phase']
                if phase == 1: ledger = row['remaining']
                elif phase == 7: route_unknown = True
                elif phase in (3, 5, 6):
                    if not route_unknown and row['remaining'] != ledger: errors['request_byte_ledger'] += 1
                    if phase == 3 and row['remaining'] and (key, now) not in snapshots:
                        errors['missing_issue_bios'] += 1
                    if phase == 5: ledger = row['remaining'] - row['completed']
                    if phase == 6 or phase == 5 and not ledger: ledger = None
    return dict(coverage='BOUNDED_ISSUE_SNAPSHOT' if supported else 'HISTORICAL_NOT_RECORDED',
                issue_sources=result, merge_transfers=transfers), dict(errors)
