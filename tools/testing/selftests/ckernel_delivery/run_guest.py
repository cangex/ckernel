#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Boot only an isolated KVM guest; no host module load, disk or networking."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--cpus', required=True)
    p.add_argument('--cc', default='gcc')
    a = p.parse_args()
    if not re.fullmatch(r'[0-9]+(?:[-,][0-9]+)*', a.cpus):
        p.error('invalid CPU list')
    build = a.build.resolve()
    output = a.output.resolve()
    if any(c.isspace() for c in str(build) + str(output)):
        p.error('initramfs build paths must not contain whitespace')
    if not Path('/dev/kvm').exists():
        p.error('KVM unavailable; no emulation fallback')
    output.mkdir(exist_ok=False)
    source = Path(__file__).with_name('guest_init.c')
    image = build / 'arch/arm64/boot/Image'
    module = build / 'drivers/ckernel/ckernel.ko'
    hashes = {str(x): sha(x) for x in (image, module, build / '.config', source)}
    subprocess.run([a.cc, '-static', '-Wall', '-Wextra', '-Werror', '-O2',
                    str(source), '-o', str(output / 'init')], check=True)
    manifest = ['dir /dev 0755 0 0', 'nod /dev/console 0600 0 0 c 5 1',
                'nod /dev/null 0666 0 0 c 1 3', 'dir /proc 0755 0 0',
                'dir /sys 0755 0 0', 'dir /cg 0755 0 0',
                f'file /init {output / "init"} 0755 0 0',
                f'file /ckernel.ko {module} 0644 0 0']
    (output / 'initramfs.list').write_text('\n'.join(manifest) + '\n')
    with (output / 'guest.cpio').open('xb') as stream:
        subprocess.run([str(build / 'usr/gen_init_cpio'), str(output / 'initramfs.list')],
                       stdout=stream, check=True)
    command = ['taskset', '-c', a.cpus, 'qemu-system-aarch64', '-machine',
               'virt,accel=kvm,gic-version=3', '-cpu', 'host', '-smp', '2',
               '-m', '2048', '-nographic', '-no-reboot', '-nic', 'none',
               '-kernel', str(image), '-initrd', str(output / 'guest.cpio'),
               '-append', 'console=ttyAMA0 rdinit=/init panic=-1 lsm=capability,apparmor apparmor=1 security=apparmor']
    (output / 'inputs.json').write_text(json.dumps(dict(hashes=hashes, command=command), indent=2))
    timed_out = False
    with (output / 'console.log').open('xb') as log:
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=log,
                                    stderr=subprocess.STDOUT, timeout=180)
            rc = result.returncode
        except subprocess.TimeoutExpired:
            timed_out, rc = True, 124
    text = (output / 'console.log').read_text(errors='replace')
    passed = rc == 0 and not timed_out and 'DELIVERY_GUEST_END failures=0' in text
    result = dict(status='PASS' if passed else 'FAIL', exit_code=rc, timed_out=timed_out,
                  scope='Finite guest smoke only; no restricted-policy/hotplug/fault coverage',
                  input_hashes=hashes)
    (output / 'result.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result))
    if not passed:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
