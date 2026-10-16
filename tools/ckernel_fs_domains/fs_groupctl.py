#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Create fresh grouped task directories; never reuse writable task state."""
import argparse
import json
from pathlib import Path
import time

from fs_domain_lifecycle import Manager
from fs_domain_plan import GIB


def specs(groups, gib, inodes, journal_mib):
    if type(groups) is not int or not 1 <= groups <= 48:
        raise ValueError('groups must be 1..48')
    if type(gib) is not int or not 1 <= gib <= 1024:
        raise ValueError('GiB per group must be 1..1024')
    if type(inodes) is not int or inodes < 1024:
        raise ValueError('invalid inode count')
    if type(journal_mib) is not int or not 16 <= journal_mib <= gib * 256:
        raise ValueError('journal must fit within one quarter of the image')
    return [dict(index=i, bytes=gib * GIB, inodes=inodes,
                 journal_mib=journal_mib) for i in range(groups)]


def create(root, slots, volumes):
    if type(slots) is not int or not 1 <= slots <= 48 or len(volumes) > slots:
        raise ValueError('require 1..48 slots and no more groups than slots')
    started = time.monotonic_ns()
    manager = Manager(root, create=True)
    try:
        manager.create_volumes(volumes)
        for slot in range(slots):
            manager.private_directory(slot, slot % len(volumes))
        for volume in manager.state['volumes']:
            manager.command(['sync', '-f', volume['mount']])
        manager.state['preparation_ns'] = time.monotonic_ns() - started
        manager.persist()
        return manager.state
    finally:
        # A failure keeps the manifest for inspection, never blind cleanup.
        manager.close()


def inspect(manager):
    manager.validate_state()
    if manager.state['state'] == 'ACTIVE':
        for volume in manager.state['volumes']:
            manager.verify_volume(volume)
    return manager.state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    new = sub.add_parser('create')
    new.add_argument('root', type=Path)
    new.add_argument('--slots', required=True, type=int)
    new.add_argument('--groups', required=True, type=int)
    new.add_argument('--gib-per-group', required=True, type=int)
    new.add_argument('--inodes-per-group', required=True, type=int)
    new.add_argument('--journal-mib-per-group', required=True, type=int)
    for name in ('inspect', 'release'):
        sub.add_parser(name).add_argument('root', type=Path)
    args = parser.parse_args()
    if args.action == 'create':
        state = create(args.root, args.slots, specs(args.groups,
            args.gib_per_group, args.inodes_per_group, args.journal_mib_per_group))
    else:
        manager = Manager(args.root)
        try:
            if args.action == 'release':
                start = time.monotonic_ns()
                manager.teardown(delete=True)
                manager.state['release_ns'] = time.monotonic_ns() - start
                manager.persist()
            state = inspect(manager)
        finally:
            manager.close()
    print(json.dumps(state, indent=2))


if __name__ == '__main__':
    main()
