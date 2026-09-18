#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Task-owned ARM64 KVM only; read host schedstat, never enable host probes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time


def task_snapshot(pid):
    start=time.monotonic_ns()
    root=Path('/proc')/str(pid)
    fields=(root/'stat').read_text().rsplit(')',1)[1].split()
    values=list(map(int,(root/'schedstat').read_text().split()))
    return dict(pid=pid,start_ticks=int(fields[19]),schedstat=values,
                begin_ns=start,end_ns=time.monotonic_ns())


def run(args):
    root=Path('/root/cis-20260916-232524')
    image,initrd,out=(p.resolve() for p in (args.image,args.initrd,args.evidence))
    if os.geteuid() or os.uname().machine!='aarch64' or any(not p.is_relative_to(root) for p in (image,initrd,out)):
        raise RuntimeError('task-owned host14 paths and ARM64 required')
    if hashlib.sha256(image.read_bytes()).hexdigest()!=args.image_sha256:
        raise ValueError('Image hash mismatch')
    if subprocess.run(['pgrep','-f','(^|/)qemu-system-aarch64( |$)'],stdout=subprocess.DEVNULL).returncode!=1:
        raise RuntimeError('another VM present; no resource takeover')
    if not out.is_dir():raise ValueError('new evidence directory required')
    os.sched_setaffinity(0,{112})
    qmp=out/'qmp.sock'; channel=out/'clock.sock'
    if qmp.exists() or channel.exists():raise ValueError('existing socket')
    command=['nice','-n','10','taskset','-c','112','qemu-system-aarch64','-machine','virt,accel=kvm,gic-version=3',
             '-cpu','host','-smp','8','-m','4096','-nographic','-no-reboot','-nic','none','-S',
             '-qmp','unix:%s,server=on,wait=off'%qmp,'-kernel',str(image),'-initrd',str(initrd),
             '-append','console=ttyAMA0 rdinit=/init panic=-1 cis_observe.wait_gate=1',
             '-device','virtio-serial-device','-chardev','socket,id=clock,path=%s,server=on,wait=off'%channel,
             '-device','virtserialport,chardev=clock,name=cis.clock']
    manifest=dict(command=command,diagnostic_only=True,host_exclusive=False,host_vcpus=list(range(80,96,2)),
                  image_sha256=args.image_sha256,initrd_sha256=hashlib.sha256(initrd.read_bytes()).hexdigest(),
                  source_head=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
                  schedstat_enabled=Path('/proc/sys/kernel/sched_schedstats').read_text().strip())
    with (out/'host-manifest.json').open('x') as stream:json.dump(manifest,stream,indent=2)
    samples=[]; errors=[]; tasks={}; clock=None
    begin_cpu=time.process_time_ns(); begin=time.monotonic_ns()
    with (out/'guest.log').open('x') as log:
        child=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT)
        try:
            for _ in range(200):
                if qmp.exists() and channel.exists():break
                if child.poll() is not None:raise RuntimeError('QEMU exited at startup')
                time.sleep(.05)
            with socket.socket(socket.AF_UNIX) as control:
                control.settimeout(10);control.connect(str(qmp));wire=control.makefile('rwb',buffering=0)
                json.loads(wire.readline())
                def request(name):
                    wire.write((json.dumps({'execute':name})+'\n').encode())
                    while True:
                        reply=json.loads(wire.readline())
                        if 'error' in reply:raise RuntimeError(reply)
                        if 'return' in reply:return reply['return']
                request('qmp_capabilities')
                for cpu in request('query-cpus-fast'):
                    index=cpu['cpu-index'];pid=cpu['thread-id']
                    os.sched_setaffinity(pid,{manifest['host_vcpus'][index]});tasks[index]=pid
                clock=socket.socket(socket.AF_UNIX);clock.settimeout(15);clock.connect(str(channel))
                request('cont')
            pending=b''
            for seq in range(600):
                if child.poll() is not None:break
                before={str(k):task_snapshot(v) for k,v in tasks.items()}
                sent=time.monotonic_ns();clock.sendall((json.dumps({'sequence':seq})+'\n').encode())
                try:
                    while b'\n' not in pending:
                        data=clock.recv(4096)
                        if not data:raise EOFError('clock channel closed')
                        pending+=data
                        if len(pending)>8192:raise ValueError('clock channel overflow')
                    line,pending=pending.split(b'\n',1);received=time.monotonic_ns()
                    reply=json.loads(line)
                    if reply.get('sequence')!=seq:raise ValueError('clock sequence mismatch')
                    samples.append(dict(**reply,host_send_ns=sent,host_receive_ns=received,schedstat=before))
                except (EOFError,ConnectionError,socket.timeout) as e:
                    errors.append(dict(stage='channel_end',sequence=seq,error=str(e)));break
                time.sleep(.1)
            child.wait(timeout=30)
        finally:
            if clock:clock.close()
            if child.poll() is None:
                child.terminate()
                try:child.wait(timeout=10)
                except subprocess.TimeoutExpired:child.kill();child.wait()
            for path in (qmp,channel):
                if path.exists():path.unlink()
            result=dict(schema='cis-host-clock-probe-v1',samples=samples,errors=errors,qemu_exit=child.returncode,
                        controller_cpu_ns=time.process_time_ns()-begin_cpu,begin_ns=begin,end_ns=time.monotonic_ns(),
                        diagnostic_only=True,host_schedstat_enabled=manifest['schedstat_enabled'])
            with (out/'clock-host.json').open('x') as stream:json.dump(result,stream,indent=2)
    text=(out/'guest.log').read_text()
    if child.returncode or 'CIS_PROFILE_VM_EXIT=0' not in text or len(samples)<3:
        raise RuntimeError('diagnostic incomplete; raw evidence retained')
    print('CLOCK_PROBE_COMPLETE',len(samples),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--image',type=Path,required=True);parser.add_argument('--image-sha256',required=True)
    parser.add_argument('--initrd',type=Path,required=True);parser.add_argument('--evidence',type=Path,required=True)
    run(parser.parse_args())
