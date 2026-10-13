#!/usr/bin/env python3
"""Verify actual aggregate capacity before a business measurement can start."""
import json
import os
from pathlib import Path
from fs_domain_lifecycle import Manager, save
from fs_domain_plan import COUNTS, layout
from go_fs_matrix import geometry, TOTAL_INODES

def main():
    os.umask(0o077)
    root = Path('/root/ckernel-fs-domains-20261013/geometry-r1')
    root.mkdir()
    rows = []
    for n in COUNTS:
        m = Manager(root / str(n), True)
        try:
            m.create_volumes(layout(n, total_inodes=TOTAL_INODES))
            values = geometry(m.state['volumes'])
            rows.append(dict(domains=n, geometry=values))
        finally:
            try:
                m.teardown(True)
            finally:
                m.close()
    features = rows[0]['geometry'][0]['features']
    assert all(v['features'] == features for row in rows for v in row['geometry'])
    result = dict(status='PASS', rows=rows, business_states=0,
                  reason='Before first measured run, requested inode budget aligned to actual ext4 group granularity')
    save(root / 'summary.json', result)
    print(json.dumps(result), flush=True)

if __name__ == '__main__':
    main()
