# SPDX-License-Identifier: GPL-2.0
"""Management-only native filter lease checks inside the exclusive test VM."""
import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

from source_switches import observe

PATH = '/sys/kernel/debug/cis_rwsem_filter'


def run(out, selected):
    rows = []
    def record(case, **facts):
        rows.append(dict(case=case,status='PASS',**facts))
        (out/'filter-control.json').write_text(json.dumps(dict(scope='root management lease ABI and killed owner; not user-namespace authorization runtime',cases=rows),indent=2))
    def rejected(case, operation, expected):
        try:
            operation()
        except OSError as exc:
            if exc.errno != expected:
                raise
        else:
            raise ValueError('filter accepted '+case)
        record(case,errno=expected)
    fd = os.open(PATH,os.O_RDWR|os.O_CLOEXEC)
    try:
        rejected('exclusive_open',lambda:os.open(PATH,os.O_RDWR|os.O_CLOEXEC),errno.EBUSY)
        for name, data in [('whitespace',b' \n'),('zero',b'0'),('unaligned',b'9'),('duplicate',b'8 8'),
                           ('too_many',b'8 16 24 32 40 48 56 64 72'),('nul',b'8\x00 16'),
                           ('oversize',b' '*257),('malformed',b'not-an-address')]:
            rejected(name,lambda data=data:os.write(fd,data),errno.EINVAL)
        text=(' '.join(hex(v) for v in selected)+'\n').encode()
        if os.write(fd,text)!=len(text):
            raise ValueError('filter write')
        rejected('immutable',lambda:os.write(fd,b'8\n'),errno.EBUSY)
        if os.read(fd,256)!=text:
            raise ValueError('filter readback')
        record('exact_readback',objects=selected)
    finally:
        os.close(fd)
    record('close_clears_selection',sources=observe(None))
    # EOF on the readiness pipe is a failure, not an assumed successful lease.
    child=subprocess.Popen([sys.executable,'-c',
        'import os,time; f=os.open(%r,os.O_RDWR); os.write(f,b"8\\n"); print("held",flush=True); time.sleep(20)'%PATH],
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        if child.stdout.readline().strip()!='held':
            raise ValueError('child filter readiness')
        rejected('child_exclusive_open',lambda:os.open(PATH,os.O_RDWR),errno.EBUSY)
        child.send_signal(signal.SIGKILL); child.wait(timeout=5)
        record('killed_owner_clears_selection',exit_code=child.returncode,sources=observe(None))
        fd=os.open(PATH,os.O_RDWR|os.O_CLOEXEC); os.close(fd)
        record('reopen_after_kill')
    finally:
        if child.poll() is None:
            child.kill(); child.wait(timeout=5)
        child.stdout.close(); child.stderr.close()
    return rows
