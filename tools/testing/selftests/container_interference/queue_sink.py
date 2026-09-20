#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Disposable namespace UDP payload verifier; losses retained, not retransmitted."""
import ctypes
import json
import os
from pathlib import Path
import socket
import struct
import sys
import time


def run():
    fd=int(sys.argv[1]); output=Path(sys.argv[2]); end=int(sys.argv[3])
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.setns(fd,0x40000000): raise OSError(ctypes.get_errno(),'setns')
    os.close(fd); seen=[set(),set()]; invalid=0; duplicate=0
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
        sock.bind(('0.0.0.0',19001)); sock.settimeout(.05)
        output.with_suffix('.ready').write_text('ready')
        while time.monotonic_ns()<end:
            try: data,_=sock.recvfrom(2048)
            except socket.timeout: continue
            if len(data)!=1024:
                invalid+=1; continue
            magic,actor,sequence=struct.unpack('!III',data[:12])
            if magic!=0x43495335 or actor not in (0,1) or sequence>=1000 or data[12:]!=bytes([0x40+actor])*1012:
                invalid+=1; continue
            if sequence in seen[actor]: duplicate+=1
            seen[actor].add(sequence)
    output.write_text(json.dumps(dict(received=[len(x) for x in seen],sequences=[sorted(x) for x in seen],
        invalid=invalid,duplicate=duplicate,end_ns=time.monotonic_ns(),delivery_scope='UDP drops allowed and counted')))


if __name__=='__main__': run()
