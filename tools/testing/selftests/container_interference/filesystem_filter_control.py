# SPDX-License-Identifier: GPL-2.0
"""Only run against disposable guest mounts, never discover host filesystems."""
import errno
import os
from pathlib import Path
from owner_report import fields
from source_switches import observe


def check():
    if not Path('/cis-disposable-vm').exists(): raise PermissionError('isolated VM required')
    endpoint='/sys/kernel/debug/cis_fs_filter'; checks=[]; generations=[]

    def denied(call,wanted):
        try: call()
        except OSError as e:
            if e.errno!=wanted: raise
        else: raise AssertionError('unexpected permission/admission success')

    fd=os.open(endpoint,os.O_RDWR|os.O_CLOEXEC)
    directory=os.open('/fs0',os.O_PATH|os.O_DIRECTORY|os.O_CLOEXEC)
    proc=os.open('/proc',os.O_PATH|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        for data in (b'',b'bad',b'-1',b'1\0',b'999999999999999999999999999'):
            denied(lambda:os.write(fd,data),errno.EINVAL)
        checks.append('invalid_input')
        denied(lambda:os.write(fd,b'999999\n'),errno.EBADF); checks.append('invalid_fd')
        denied(lambda:os.write(fd,str(proc).encode()),errno.EINVAL); checks.append('non_ext4_rejected')
        denied(lambda:os.open(endpoint,os.O_RDWR),errno.EBUSY); checks.append('exclusive')
        os.write(fd,('%d\n'%directory).encode())
        denied(lambda:os.write(fd,('%d\n'%directory).encode()),errno.EBUSY); checks.append('immutable')
        row=fields(os.read(fd,160).decode())
        if row.get('version')!=1 or not row.get('lease'): raise ValueError('lease readback')
        generations.append(row['lease'])
        denied(lambda:os.write(fd,('%d\n'%directory).encode()),errno.EINVAL); checks.append('read_offset_rejected')
        child=os.fork()
        if not child:
            try:
                os.setgroups([]); os.setgid(65534); os.setuid(65534)
                denied(lambda:os.read(fd,160),errno.EPERM)
                denied(lambda:os.write(fd,('%d\n'%directory).encode()),errno.EPERM)
                os._exit(0)
            except BaseException: os._exit(1)
        _,status=os.waitpid(child,0)
        if status: raise ValueError('inherited control privilege')
        checks.append('inherited_fd_not_authority')
    finally:
        os.close(fd); os.close(directory); os.close(proc)
    fd=os.open(endpoint,os.O_RDWR|os.O_CLOEXEC); directory=os.open('/fs0',os.O_PATH|os.O_DIRECTORY)
    try:
        os.write(fd,('%d\n'%directory).encode()); row=fields(os.read(fd,160).decode()); generations.append(row['lease'])
    finally: os.close(fd); os.close(directory)
    if generations[1]<=generations[0]: raise ValueError('lease generation reused')
    checks.append('new_lease_generation')
    return dict(status='PASS',checks=checks,generations=generations,idle=observe(None),
                unverified=['close while active probe retains outstanding sampled operation'])
