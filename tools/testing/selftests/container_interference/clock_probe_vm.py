#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Bounded two-container OFF diagnostic, with a separate host clock channel."""
import json
import os
from pathlib import Path
import select
import subprocess
import threading
import time


def main():
    if not Path('/cis-disposable-vm').exists() or os.geteuid() or os.uname().machine!='aarch64':
        raise RuntimeError('dedicated ARM64 VM only')
    os.sched_setaffinity(0,{7})
    out=Path('/tmp/clock-probe');out.mkdir()
    root=Path('/sys/fs/cgroup/cis-clock');root.mkdir()
    groups=[root/('role%d'%i) for i in range(2)]
    for p in groups:p.mkdir()
    stop=threading.Event(); errors=[]; cpu=[]

    def serve():
        begin=time.thread_time_ns(); fd=None
        try:
            ports=[p.parent.name for p in Path('/sys/class/virtio-ports').glob('*/name') if p.read_text().strip()=='cis.clock']
            if len(ports)!=1:raise RuntimeError('one named virtio clock channel required')
            fd=os.open('/dev/'+ports[0],os.O_RDWR|os.O_NONBLOCK)
            pending=b''; count=0
            while not stop.is_set() and count<1200:
                if not select.select([fd],[],[],.1)[0]:continue
                part=os.read(fd,4096)
                if not part:break
                pending+=part
                if len(pending)>8192:raise ValueError('clock channel overflow')
                while b'\n' in pending:
                    line,pending=pending.split(b'\n',1)
                    received=time.monotonic_ns();query=json.loads(line)
                    reply=json.dumps(dict(sequence=query['sequence'],guest_receive_ns=received,
                                          guest_send_ns=time.monotonic_ns())).encode()+b'\n'
                    if os.write(fd,reply)!=len(reply):raise OSError('short clock reply')
                    count+=1
            if count<3:raise RuntimeError('clock handshake absent')
        except Exception as e:errors.append(str(e))
        finally:
            if fd is not None:os.close(fd)
            cpu.append(time.thread_time_ns()-begin)

    thread=threading.Thread(target=serve);thread.start()
    children=[]
    try:
        time.sleep(1)
        start=time.monotonic_ns()+500_000_000
        for role in range(2):
            log=(out/('workload%d.log'%role)).open('x')
            child=subprocess.Popen(['/session_launch',str(groups[role]),str(role*2),'/workload','open-loop','2',str(start),'2000','timeline'],stdout=log,stderr=log)
            children.append((child,log))
        for child,log in children:
            if child.wait(timeout=15):raise RuntimeError('diagnostic workload failed')
            log.close()
        time.sleep(1)
    finally:
        for child,log in children:
            if child.poll() is None:child.terminate();child.wait(timeout=5)
            log.close()
        stop.set();thread.join(timeout=5)
    if thread.is_alive() or errors:raise RuntimeError(errors or ['clock thread alive'])
    (out/'clock-guest.json').write_text(json.dumps(dict(diagnostic_only=True,clock_thread_cpu_ns=cpu,
           errors=errors,clock='guest_monotonic',limits='extra clock traffic; timeline output after window; not acceptance')))
    print('CIS_CLOCK_PROBE_DONE=0',flush=True)


if __name__=='__main__':main()
