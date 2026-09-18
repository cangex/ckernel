# SPDX-License-Identifier: GPL-2.0
"""Explicit disposable-VM experiment permission, never a P1 acceptance receipt."""
import json
import os
from pathlib import Path
import stat

from periodic_plan import digest

SOURCE_KEYS = ('controller_sha256', 'worker_sha256', 'residue_sha256', 'bpf_sha256',
               'support_sha256', 'kernel_release', 'kernel_notes_sha256', 'kernel_cmdline_sha256')
LIMITS = dict(registered_roots=4, active_targets=2, window_ms=2000,
              sessions=32, lifetime_s=1200)


def machine_model():
    path = Path('/sys/firmware/devicetree/base/model')
    if path.is_file():
        return path.read_bytes().rstrip(b'\0').decode()
    # This fixed guest kernel does not export OF sysfs. Read only the bounded
    # boot log, without clearing it; an absent/overwritten model fails closed.
    fd = os.open('/dev/kmsg', os.O_RDONLY | os.O_NONBLOCK)
    try:
        for _ in range(512):
            try:
                line = os.read(fd, 4096).decode(errors='replace')
            except BlockingIOError:
                break
            if ';Machine model: ' in line:
                return line.split(';Machine model: ', 1)[1].strip()
    finally:
        os.close(fd)
    return 'unknown'


def environment():
    memory = int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines()
                      if line.startswith('MemTotal:')))*1024
    return dict(boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                architecture=os.uname().machine, page_bytes=os.sysconf('SC_PAGE_SIZE'),
                online_cpus=Path('/sys/devices/system/cpu/online').read_text().strip(),
                memory_bytes=memory, marker=Path('/cis-disposable-vm').is_file(),
                machine_model=machine_model())


def check_environment(env):
    if (env.get('marker') is not True or env.get('architecture') != 'aarch64'
            or env.get('page_bytes') != 4096 or env.get('online_cpus') != '0-7'
            or env.get('machine_model') != 'linux,dummy-virt'
            or not 3*2**30 <= env.get('memory_bytes', 0) <= 4*2**30):
        raise PermissionError('prototype requires the declared 8-vCPU/4-GiB disposable ARM64 QEMU guest')


def create(manifest, env, time_ns):
    check_environment(env)
    return dict(schema='cis-prototype-permit-v1', source={key: manifest[key] for key in SOURCE_KEYS},
                environment=env, limits=LIMITS, created_ns=time_ns,
                expires_ns=time_ns+LIMITS['lifetime_s']*10**9,
                authorization='isolated functional prototype; P99 record-only',
                performance_certification='NOT_ACCEPTED', p1_receipt=False)


def validate(value, manifest, env, time_ns):
    check_environment(env)
    if (value.get('schema') != 'cis-prototype-permit-v1' or value.get('p1_receipt') is not False
            or value.get('performance_certification') != 'NOT_ACCEPTED'
            or value.get('environment') != env or value.get('limits') != LIMITS
            or value.get('source') != {key: manifest[key] for key in SOURCE_KEYS}):
        raise ValueError('prototype permit environment/source/contract mismatch')
    begin, end = value.get('created_ns'), value.get('expires_ns')
    if (type(begin) is not int or type(end) is not int or not 0 <= begin <= time_ns < end
            or end-begin != LIMITS['lifetime_s']*10**9):
        raise ValueError('prototype permit expired or invalid')
    return digest(value)


def load(path, manifest, env, time_ns):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid or info.st_mode & 0o077 or info.st_size > 16384:
            raise PermissionError('prototype permit must be bounded, private and root-owned')
        value = json.loads(os.read(fd, 16385))
    finally:
        os.close(fd)
    return value, validate(value, manifest, env, time_ns)


def admit(value, manifest, env, time_ns, root_count, sessions, window_ms):
    validate(value, manifest, env, time_ns)
    if root_count > LIMITS['registered_roots'] or sessions >= LIMITS['sessions'] or window_ms > LIMITS['window_ms']:
        raise ValueError('prototype experiment capacity exhausted')


if __name__=='__main__':
    import argparse
    import time
    from session import source_manifest
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker',required=True)
    parser.add_argument('--residue',required=True)
    parser.add_argument('--bpf',required=True)
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    if os.geteuid()!=0:raise PermissionError('administrator required')
    env=environment()
    value=create(source_manifest(args,env['boot_id']),env,time.monotonic_ns())
    fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as output:
        json.dump(value,output,indent=2)
        output.write('\n')
        output.flush();os.fsync(output.fileno())
    print('prototype permit created; P1 remains NOT_ACCEPTED')
