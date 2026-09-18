#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run a single bounded X-series guest, never boot or change the host kernel."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time


def sha(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''): value.update(block)
    return value.hexdigest()


def run(args):
    os.umask(0o077)
    base = Path('/root/cis-20260916-232524')
    scratch = Path('/dev/shm/cis-x-20260918')
    source = Path(args.source).resolve() if args.source else base/'periodic/kernel'
    evidence, image, initrd = [Path(x).resolve() for x in (args.evidence, args.image, args.initrd)]
    if os.uname().machine != 'aarch64' or os.geteuid() != 0:
        raise PermissionError('dedicated ARM64 development host required')
    if (not evidence.is_relative_to(base/'evidence') or not image.is_relative_to(base)
            or not initrd.is_relative_to(scratch) or not evidence.is_dir()):
        raise ValueError('outside dedicated artifact directories')
    if source != base/'periodic/kernel' and not source.is_relative_to(scratch):
        raise ValueError('source outside dedicated checkout directories')
    lock = os.open(base/'x-vm.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    if subprocess.run(['pgrep', '-f', '(^|/)qemu-system-aarch64( |$)'], stdout=subprocess.DEVNULL).returncode != 1:
        raise RuntimeError('another QEMU exists; do not compete')
    if sha(image) != args.image_sha256: raise ValueError('Image digest mismatch')
    stat = os.statvfs('/')
    if stat.f_bavail*stat.f_frsize < 4 << 30: raise RuntimeError('root free reserve')
    stamp = args.label+'-'+time.strftime('%Y%m%d-%H%M%S')
    qmp = base/(stamp+'.qmp'); serial = evidence/(stamp+'.log')
    cpu_map = list(range(80, 96, 2))
    command = ['nice', '-n', '10', 'taskset', '-c', '112', 'qemu-system-aarch64',
               '-machine', 'virt,accel=kvm,gic-version=3', '-cpu', 'host', '-smp', '8', '-m', '4096',
               '-nographic', '-no-reboot', '-nic', 'none', '-S', '-qmp', 'unix:%s,server=on,wait=off'%qmp,
               '-kernel', str(image), '-initrd', str(initrd),
               '-append', 'console=ttyAMA0 rdinit=/init panic=-1 cis_observe.wait_gate=1']
    manifest = dict(command=command, image_sha256=sha(image), initrd_sha256=sha(initrd),
                    host_cpus=cpu_map, manager_cpu=112, host_exclusive=False, scope='isolated_KVM_only',
                    timeout_s=args.timeout, source_head=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip(),
                    source_dirty=subprocess.check_output(['git','-C',str(source),'status','--porcelain'],text=True))
    with (evidence/(stamp+'.manifest.json')).open('x') as stream: json.dump(manifest, stream, indent=2)
    def interrupted(number, frame): raise InterruptedError('VM runner interrupted')
    for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT): signal.signal(number, interrupted)
    with serial.open('x') as output:
        child = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        try:
            deadline = time.monotonic()+10
            while not qmp.exists():
                if time.monotonic()>deadline or child.poll() is not None: raise TimeoutError('QMP readiness')
                time.sleep(.05)
            with socket.socket(socket.AF_UNIX) as sock:
                sock.settimeout(10); sock.connect(str(qmp)); stream = sock.makefile('rwb', buffering=0)
                json.loads(stream.readline())
                def qcommand(name):
                    stream.write((json.dumps(dict(execute=name))+'\n').encode())
                    for unused in range(100):
                        reply=json.loads(stream.readline())
                        if 'error' in reply: raise RuntimeError(reply)
                        if 'return' in reply: return reply['return']
                    raise RuntimeError('QMP response budget')
                qcommand('qmp_capabilities')
                for cpu in qcommand('query-cpus-fast'):
                    os.sched_setaffinity(cpu['thread-id'], {cpu_map[cpu['cpu-index']]})
                qcommand('cont')
            deadline = time.monotonic()+args.timeout
            while child.poll() is None:
                stat=os.statvfs('/')
                if time.monotonic()>deadline or serial.stat().st_size>128 << 20 or stat.f_bavail*stat.f_frsize<4 << 30:
                    raise RuntimeError('VM time, log or disk budget exceeded')
                time.sleep(.5)
        finally:
            if child.poll() is None:
                child.terminate()
                try: child.wait(timeout=10)
                except subprocess.TimeoutExpired: child.kill(); child.wait()
            if qmp.exists(): qmp.unlink()
    text = serial.read_text(errors='replace')
    passed = child.returncode == 0 and '\nCIS_PROFILE_VM_EXIT=0\n' in text
    with (evidence/(stamp+'.runner-result.json')).open('x') as output:
        json.dump(dict(status='PASS' if passed else 'FAIL', serial=str(serial), manifest=manifest,
                       phase_complete=False), output, indent=2)
    print('VM_LOG='+str(serial), flush=True)
    print('VM_STATUS='+('PASS' if passed else 'FAIL'), flush=True)
    return 0 if passed else 1


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    for name in ('image','image-sha256','initrd','evidence'): parser.add_argument('--'+name,required=True)
    parser.add_argument('--source', help='frozen guest-tool checkout, if staged independently')
    parser.add_argument('--label', choices=('x0-control','x0-fault','x0-expiry','x1-sync'), required=True)
    parser.add_argument('--timeout', type=int, choices=(900,1500,1800), default=900)
    raise SystemExit(run(parser.parse_args()))
