#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Real ENOSPC before worker launch. Only in a dedicated disposable VM."""
import json
import os
from pathlib import Path
import socket
import subprocess
import time


def request(endpoint, op, **fields):
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as connection:
        connection.settimeout(2)
        connection.connect(endpoint)
        connection.send(json.dumps(dict(version=1, op=op, **fields)).encode())
        response = json.loads(connection.recv(8192))
        if not response['ok']:
            raise RuntimeError(response)
        return response['data']


def run():
    if not Path('/cis-disposable-vm').exists() or os.geteuid() or os.uname().machine != 'aarch64':
        raise RuntimeError('isolated ARM64 VM only')
    out = Path('/tmp/session-evidence')
    out.mkdir(exist_ok=True)
    mount = Path('/tmp/cis-full-disk')
    mount.mkdir(mode=0o700)
    subprocess.run(['mount', '-t', 'tmpfs', '-o', 'size=1m,mode=0700', 'none', str(mount)], check=True)
    endpoint = '/run/cis-full-disk.sock'
    log = (out/'storage-controller.log').open('x')
    child = subprocess.Popen(['/usr/bin/python3', '/profile/session.py', '--socket', endpoint,
                              '--directory', str(mount/'records'), '--worker', '/profile/session-worker',
                              '--bpf', '/profile/cis.bpf.o', '--residue', '/profile/session-residue', 'daemon'],
                             stdout=log, stderr=log)
    root = Path('/sys/fs/cgroup/cis-full-disk')
    root.mkdir()
    try:
        for _ in range(500):
            if Path(endpoint).exists(): break
            if child.poll() is not None: raise RuntimeError('controller start failed')
            time.sleep(.01)
        target = request(endpoint, 'register', path=str(root))['target']
        with (mount/'owned-filler').open('xb', buffering=0) as filler:
            while True:
                try:
                    filler.write(b'x'*65536)
                except OSError as error:
                    if error.errno != 28: raise
                    break
        start = time.monotonic_ns()
        sid = request(endpoint, 'start', collector='ip', targets=[target], nonce='realDiskFull', window_ms=2000)['session_id']
        elapsed = time.monotonic_ns()-start
        for _ in range(200):
            result = request(endpoint, 'status', session=sid)
            if result.get('finalized'): break
            time.sleep(.01)
        assert result['result'] == 'FAILED' and result['objects_absent'], result
        assert 'worker_pid' not in result and 'No space left' in result['io_error'], result
        assert request(endpoint, 'status')['state'] == 'FAULTED'
        request(endpoint, 'cancel', session=sid)
        report = dict(real_enospc=True, failure_record=result, start_response_ns=elapsed,
                      no_worker_created=True, status_cancel_responsive=True)
        (out/'storage-result.json').write_text(json.dumps(report, indent=2))
        print('CIS_PROFILE_STORAGE '+json.dumps(report), flush=True)
    finally:
        if child.poll() is None:
            request(endpoint, 'stop')
            child.wait(timeout=10)
        log.close()
        subprocess.run(['umount', str(mount)], check=True)
        root.rmdir()


if __name__ == '__main__': run()
