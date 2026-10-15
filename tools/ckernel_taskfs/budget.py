# SPDX-License-Identifier: GPL-2.0
"""No overcommit credit for shared blocks; physical and logical gates differ."""
GIB = 1024**3
MIB = 1024**2


def validate_config(c):
    for key in ('data_bytes', 'metadata_bytes', 'chunk_sectors', 'max_branches', 'root_floor', 'max_pending'):
        if type(c.get(key)) is not int or c[key] <= 0:
            raise ValueError('invalid '+key)
    if c['root_floor'] < 6*GIB or c['data_bytes'] % 4096 or c['metadata_bytes'] % 4096:
        raise ValueError('floor or alignment')
    if not 64*MIB <= c['metadata_bytes'] <= 16*GIB:
        raise ValueError('metadata budget')
    if c['chunk_sectors'] % 128 or not 128 <= c['chunk_sectors'] <= 2097152:
        raise ValueError('native chunk range')
    if c['max_branches'] > 64 or c['max_pending'] > c['max_branches']:
        raise ValueError('bounded lifecycle required')
    return c


def host_gate(free, c, allocate=False):
    needed = c['root_floor'] + GIB
    if allocate:
        needed += c['data_bytes'] + c['metadata_bytes']
    if free < needed:
        raise RuntimeError('host capacity admission')


def parse_pool_status(text):
    fields = text.strip().split()
    if len(fields) < 10 or fields[2] != 'thin-pool':
        raise RuntimeError('invalid or failed pool status')
    meta = [int(v) for v in fields[4].split('/')]
    data = [int(v) for v in fields[5].split('/')]
    if len(meta) != 2 or len(data) != 2 or min(meta+data) < 0 or min(meta[1],data[1]) == 0:
        raise RuntimeError('invalid pool counters')
    if fields[7] != 'rw' or 'needs_check' in fields:
        raise RuntimeError('pool unhealthy')
    return dict(metadata_used=meta[0], metadata_total=meta[1], data_used=data[0], data_total=data[1], raw=text.strip())


def pool_gate(status, reserved_logical, requested, c, branches):
    if branches >= c['max_branches']:
        raise RuntimeError('branch count admission')
    if reserved_logical + requested > c['data_bytes'] * 8 // 10:
        raise RuntimeError('no logical overcommit')
    if status['data_used']*10 >= status['data_total']*9:
        raise RuntimeError('thin data high water')
    if status['metadata_used']*10 >= status['metadata_total']*8:
        raise RuntimeError('thin metadata high water')
