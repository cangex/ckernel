# SPDX-License-Identifier: GPL-2.0
"""Read-only mount topology checks; never alter a foreign namespace."""
import os
from pathlib import Path


def record(line):
    fields = line.split()
    split = fields.index('-')
    return dict(id=fields[0], dev=fields[2], root=fields[3], target=fields[4],
                tags=set(fields[6:split]), fstype=fields[split + 1])


def mirrors(rows, host_namespace, host_id, dev, target):
    hosts = [r for ns, r in rows if ns == host_namespace and r['id'] == str(host_id)]
    if len(hosts) != 1:
        raise RuntimeError('host mount identity missing or ambiguous')
    host = hosts[0]
    shared = [t.split(':', 1)[1] for t in host['tags'] if t.startswith('shared:')]
    if len(shared) != 1:
        raise RuntimeError('not a registered shared mount')
    peer = shared[0]
    approved = set()
    for ns, row in rows:
        if row['dev'] != dev:
            continue
        if row['root'] != '/' or row['target'] != target or row['fstype'] != 'ext4':
            raise RuntimeError('non-mirror filesystem reference')
        if not ({'shared:' + peer, 'master:' + peer} & row['tags']):
            raise RuntimeError('unrelated mount propagation group')
        approved.add((ns, row['id']))
    return approved


def inventory(dev):
    rows = []
    seen = set()
    for process in Path('/proc').iterdir():
        if not process.name.isdigit():
            continue
        try:
            ns = os.readlink(process / 'ns/mnt')
            if ns in seen:
                continue
            text = (process / 'mountinfo').read_text()
            seen.add(ns)
            rows.extend((ns, r) for r in map(record, text.splitlines()) if r['dev'] == dev)
        except (FileNotFoundError, ProcessLookupError):
            continue
    return rows
