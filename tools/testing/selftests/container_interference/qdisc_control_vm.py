#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Administrative queue lease tests only, not public-traffic acceptance."""
import ctypes
import errno
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
from owner_report import fields
from source_switches import observe


def noop_probe():
    if os.uname().machine!='aarch64': raise RuntimeError('ARM64 guest required')
    libc=ctypes.CDLL(None,use_errno=True); libc.syscall.restype=ctypes.c_long
    def bpf(command,attribute):
        data=ctypes.create_string_buffer(attribute)
        result=libc.syscall(ctypes.c_long(280),ctypes.c_int(command),ctypes.byref(data),ctypes.c_uint(len(attribute)))
        if result<0: raise OSError(ctypes.get_errno(),os.strerror(ctypes.get_errno()))
        return result
    insn=ctypes.create_string_buffer(struct.pack('<BBhiBBhi',0xb7,0,0,0,0x95,0,0,0))
    license=ctypes.create_string_buffer(b'GPL\0'); log=ctypes.create_string_buffer(65536)
    prog=bpf(5,struct.pack('<IIQQIIQII16sII',17,2,ctypes.addressof(insn),ctypes.addressof(license),
        1,len(log),ctypes.addressof(log),0,0,b'cis_queue_test',0,0))
    name=ctypes.create_string_buffer(b'cis_qdisc_state\0')
    try: link=bpf(17,struct.pack('<QII',ctypes.addressof(name),prog,0))
    except BaseException: os.close(prog); raise
    return prog,link


def run():
    if not Path('/cis-disposable-vm').exists(): raise PermissionError('disposable VM required')
    os.umask(0o077); os.sched_setaffinity(0,{7})
    out=Path('/tmp/y5-control-evidence'); out.mkdir(mode=0o700)
    log=[]; checks=[]; leases=[]; endpoint='/sys/kernel/debug/cis_queue_filter'
    def command(*args):
        p=subprocess.run(args,text=True,capture_output=True,timeout=10)
        log.append(dict(command=args,returncode=p.returncode,stdout=p.stdout,stderr=p.stderr))
        (out/'commands.json').write_text(json.dumps(log,indent=2))
        if p.returncode: raise ValueError(log[-1])
        return p.stdout
    def denied(action,wanted):
        try: action()
        except OSError as e:
            if e.errno!=wanted: raise
        else: raise ValueError('expected rejection')
    def readback(fd): return fields(os.pread(fd,256,0).decode())
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); fd=link=prog=None
    created=[]
    try:
        for name in ('cisy5a','cisy5b'):
            command('/usr/sbin/ip','link','add',name,'type','dummy'); created.append(name)
            command('/usr/sbin/ip','link','set',name,'txqueuelen','64','up')
            command('/usr/sbin/tc','qdisc','replace','dev',name,'root','handle','1:','pfifo','limit','16')
        indexes=[socket.if_nametoindex(name) for name in created]
        def select(fd,index): os.write(fd,('%d %d 0\n'%(sock.fileno(),index)).encode())
        fd=os.open(endpoint,os.O_RDWR|os.O_CLOEXEC)
        for data in (b'',b'bad',b'-1 1 0',b'4294967299 1 0',b'1 4294967297 0',b'1 1 0 extra',b'1 1 0\0'):
            denied(lambda:os.write(fd,data),errno.EINVAL)
        checks.append('strict_input_and_overflow')
        denied(lambda:os.write(fd,b'999999 1 0'),errno.EBADF); checks.append('invalid_socket_fd')
        denied(lambda:os.write(fd,('%d 2147483647 0'%sock.fileno()).encode()),errno.ENODEV)
        denied(lambda:os.write(fd,('%d %d 9999'%(sock.fileno(),indexes[0])).encode()),errno.EINVAL)
        checks.append('invalid_device_and_queue')
        denied(lambda:os.open(endpoint,os.O_RDWR),errno.EBUSY); checks.append('exclusive')
        select(fd,indexes[0]); first=readback(fd); leases.append(first)
        if first['valid']!=1 or first['ifindex']!=indexes[0] or first['queue']!=0 or first['handle']!=65536:
            raise ValueError(first)
        denied(lambda:select(fd,indexes[1]),errno.EBUSY); checks.append('immutable_selection')
        child=os.fork()
        if not child:
            try:
                os.setgroups([]); os.setgid(65534); os.setuid(65534)
                denied(lambda:readback(fd),errno.EPERM)
                denied(lambda:select(fd,indexes[1]),errno.EPERM)
                os._exit(0)
            except BaseException: os._exit(1)
        _,status=os.waitpid(child,0)
        if status: raise ValueError('inherited authority')
        checks.append('inherited_fd_not_authority')
        prog,link=noop_probe()
        active=Path('/sys/kernel/debug/cis_sources').read_text()
        if fields(active).get('qdisc')!=1 or fields(active).get('net')!=0: raise ValueError(active)
        command('/usr/sbin/tc','qdisc','change','dev',created[0],'root','handle','1:','pfifo','limit','32')
        changed=readback(fd)
        if changed['valid']!=0 or changed['lease']!=first['lease']: raise ValueError(changed)
        checks.append('same_object_change_invalidates')
        os.close(fd); fd=None
        denied(lambda:os.open(endpoint,os.O_RDWR),errno.EBUSY)
        revoked=Path('/sys/kernel/debug/cis_sources').read_text()
        if fields(revoked).get('qdisc_filter')!=0: raise ValueError(revoked)
        os.close(link); link=None; os.close(prog); prog=None
        checks.append('revoke_attached_noop_probe')
        for index in indexes:
            fd=os.open(endpoint,os.O_RDWR|os.O_CLOEXEC); select(fd,index)
            row=readback(fd); leases.append(row)
            if row['valid']!=1 or row['lease']<=leases[-2]['lease']: raise ValueError('lease generation')
            os.close(fd); fd=None
        if leases[-1]['qdisc']==leases[-2]['qdisc'] or leases[-1]['handle']!=leases[-2]['handle']:
            raise ValueError('independent queue truth')
        checks.append('same_handle_different_resource')
        fd=os.open(endpoint,os.O_RDWR|os.O_CLOEXEC); select(fd,indexes[0]); before=readback(fd)
        command('/usr/sbin/tc','qdisc','replace','dev',created[0],'root','handle','2:','pfifo','limit','16')
        replaced=readback(fd)
        if replaced['valid']!=0 or replaced['lease']!=before['lease']: raise ValueError(replaced)
        os.close(fd); fd=None; checks.append('replacement_invalidates')
        idle=observe(None)
        result=dict(status='PASS_CONTROL_ONLY',checks=checks,leases=leases,active=active,revoked=revoked,
            changed=changed,replaced=replaced,idle=idle,
            unverified=['packet/source attribution','source storms','concurrent in-flight revocation','public traffic costs'])
        (out/'result.json').write_text(json.dumps(result,indent=2))
    finally:
        for handle in (link,fd,prog):
            if handle is not None: os.close(handle)
        sock.close()
        for name in reversed(created): command('/usr/sbin/ip','link','del',name)


if __name__=='__main__': run()
