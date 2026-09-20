# SPDX-License-Identifier: GPL-2.0
"""Only run against disposable guest mounts, never discover host filesystems."""
import errno
import ctypes
import os
from pathlib import Path
import struct
from owner_report import fields
from source_switches import observe


def close_attached():
    # This two-instruction probe tests lease cleanup only; it collects no data.
    if os.uname().machine!='aarch64': raise RuntimeError('isolated ARM64 test required')
    libc=ctypes.CDLL(None,use_errno=True); libc.syscall.restype=ctypes.c_long
    def bpf(command,attribute):
        buf=ctypes.create_string_buffer(attribute)
        ret=libc.syscall(ctypes.c_long(280),ctypes.c_int(command),ctypes.byref(buf),ctypes.c_uint(len(attribute)))
        if ret<0: raise OSError(ctypes.get_errno(),os.strerror(ctypes.get_errno()))
        return ret
    instructions=ctypes.create_string_buffer(struct.pack('<BBhiBBhi',0xb7,0,0,0,0x95,0,0,0))
    license=ctypes.create_string_buffer(b'GPL\0'); log=ctypes.create_string_buffer(65536)
    prog=bpf(5,struct.pack('<IIQQIIQII16sII',17,2,ctypes.addressof(instructions),
             ctypes.addressof(license),1,len(log),ctypes.addressof(log),0,0,b'cis_lease_test',0,0))
    name=ctypes.create_string_buffer(b'cis_fs_state\0'); link=fd=directory=None
    try:
        fd=os.open('/sys/kernel/debug/cis_fs_filter',os.O_RDWR|os.O_CLOEXEC)
        directory=os.open('/fs0',os.O_PATH|os.O_DIRECTORY|os.O_CLOEXEC)
        os.write(fd,str(directory).encode())
        link=bpf(17,struct.pack('<QII',ctypes.addressof(name),prog,0))
        before=Path('/sys/kernel/debug/cis_fs_audit').read_text()
        os.close(fd); fd=None
        revoked=Path('/sys/kernel/debug/cis_fs_audit').read_text()
        if fields(before.splitlines()[0]).get('enabled')!=1 or fields(revoked.splitlines()[0]).get('lease_active')!=0:
            raise ValueError('lease revocation/source state')
        try: fd=os.open('/sys/kernel/debug/cis_fs_filter',os.O_RDWR|os.O_CLOEXEC)
        except OSError as e:
            if e.errno!=errno.EBUSY: raise
        else: raise ValueError('lease replacement with active old probe')
        os.close(link); link=None
        fd=os.open('/sys/kernel/debug/cis_fs_filter',os.O_RDWR|os.O_CLOEXEC)
        os.write(fd,str(directory).encode())
        return dict(status='PASS',before=before,revoked=revoked,
                    scope='active no-op probe, no claim of an in-flight filesystem operation')
    finally:
        for handle in (link,fd,directory,prog):
            if handle is not None: os.close(handle)


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
    revocation=close_attached(); checks.append('close_attached_and_replace_after_detach')
    return dict(status='PASS',checks=checks,generations=generations,revocation=revocation,idle=observe(None),
                unverified=['close while active probe retains outstanding sampled operation'])
