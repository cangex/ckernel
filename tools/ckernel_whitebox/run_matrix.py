"""Fixed shared-kernel exploration, QMP-pinned vCPUs and compact retention."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import time
from prepare_business_core import W, sha, run
from matrix_checks import validate

B = Path('/home/ckernel-whitebox-business-20261009-build-r3')
D = W/'matrix-r5'
KEEP_LAYERS = False


class QMP:
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(10)
        self.sock.connect(str(path))
        self.stream = self.sock.makefile('rwb')
        assert 'QMP' in json.loads(self.stream.readline())
        self.call('qmp_capabilities')

    def call(self, command):
        self.stream.write((json.dumps({'execute': command})+'\n').encode())
        self.stream.flush()
        while True:
            record = json.loads(self.stream.readline())
            if 'error' in record:
                raise RuntimeError(record)
            if 'return' in record:
                return record['return']

    def close(self):
        self.stream.close()
        self.sock.close()


def stop(p):
    if p.poll() is None:
        os.killpg(p.pid, signal.SIGTERM)
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait()


def execute(root, kind, variant, copies, round_id, build):
    d = root/f'{round_id}-{variant}-{copies}'
    d.mkdir()
    assert shutil.disk_usage('/').free > (10 if kind == 'go' else 8)*1024**3
    for stem in ('guest', 'business'):
        run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'raw', '-b', str(D/kind/(stem+'.ext4')), str(d/(stem+'.qcow2'))])
    qmp_path = Path('/run')/('w1-matrix-'+str(os.getpid())+'.sock')
    assert not qmp_path.exists()
    image = build['builds'][variant]['image']
    assert sha(Path(image)) == build['builds'][variant]['image_sha256']
    command = ['taskset', '-c', '48-51', 'numactl', '--membind=0', 'qemu-system-aarch64',
               '-machine', 'virt,accel=kvm,gic-version=3', '-cpu', 'host', '-smp', '52', '-m', '53248',
               '-nographic', '-no-reboot', '-nic', 'none', '-S', '-qmp', f'unix:{qmp_path},server=on,wait=off',
               '-kernel', image]
    for stem, ident in [('business', 'business'), ('guest', 'root')]:
        command += ['-drive', f'file={d}/{stem}.qcow2,format=qcow2,if=none,id={ident}', '-device', f'virtio-blk-device,drive={ident}']
    command += ['-append', 'console=ttyAMA0 root=/dev/vda rw init=/init panic=-1 lsm=capability,selinux selinux=1 enforcing=1 w1copies='+str(copies)+' w1variant='+variant]
    (d/'command.json').write_text(json.dumps(command))
    record = dict(status='FAIL', workload=kind, variant=variant, copies=copies, round=round_id,
                  config_sha256=build['builds'][variant]['config_sha256'], image_sha256=build['builds'][variant]['image_sha256'])
    started = time.monotonic()
    p = None
    qmp = None
    try:
        with (d/'console.log').open('x') as log:
            p = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            while not qmp_path.exists():
                assert p.poll() is None and time.monotonic()-started < 20, 'QMP startup'
                time.sleep(.05)
            qmp = QMP(qmp_path)
            cpus = qmp.call('query-cpus-fast')
            assert sorted(c['cpu-index'] for c in cpus) == list(range(52))
            mapping = []
            for c in cpus:
                i, tid = c['cpu-index'], c['thread-id']
                os.sched_setaffinity(tid, {i})
                assert os.sched_getaffinity(tid) == {i}
                mapping.append(dict(vcpu=i, tid=tid, host_cpu=i))
            record['mapping'] = mapping
            qmp.call('cont')
            while p.poll() is None:
                assert time.monotonic()-started < 900, 'VM deadline'
                assert shutil.disk_usage('/').free > 6*1024**3, 'root reserve'
                assert (d/'console.log').stat().st_size < 8*1024**2, 'console budget'
                time.sleep(.5)
            assert p.returncode == 0, 'QEMU failed'
        text = (d/'console.log').read_text(errors='replace')
        record.update(validate(text, copies))
    except Exception as exc:
        record.update(status='FAIL', error=repr(exc))
    finally:
        if p:
            stop(p)
        if qmp:
            qmp.close()
        if qmp_path.exists():
            qmp_path.unlink()
        record['elapsed_with_preparation_grading_shutdown_s'] = time.monotonic()-started
        record['allocated_disk_bytes'] = sum(x.stat().st_blocks*512 for x in d.glob('*.qcow2'))
        record['console_sha256'] = sha(d/'console.log')
        (d/'result.json').write_text(json.dumps(record, indent=2))
    if record['status'] == 'PASS' and not KEEP_LAYERS:
        # Only leaf layers created by this invocation, after its VM has fully exited.
        removed = []
        for f in d.glob('*.qcow2'):
            for proc in Path('/proc').glob('[0-9]*/fd/*'):
                try:
                    assert proc.resolve() != f.resolve(), 'layer remains open'
                except (PermissionError, FileNotFoundError):
                    pass
            removed.append(dict(path=str(f), bytes=f.stat().st_blocks*512))
            f.unlink()
        (d/'cleanup.json').write_text(json.dumps(dict(time=time.time(), category='completed own leaf overlays', removed=removed)))
    print(json.dumps({k: record.get(k) for k in ('status', 'workload', 'variant', 'copies', 'round', 'target_s', 'batch_s', 'error')}), flush=True)
    return record


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('workload', choices=['core', 'go'])
    parser.add_argument('--mode', choices=['smoke', 'pilot', 'formal', 'diagnostic', 'baseline-diagnostic'], required=True)
    parser.add_argument('--formal-plan')
    parser.add_argument('--stamp', required=True)
    args = parser.parse_args()
    os.sched_setaffinity(0, {48, 49, 50, 51})
    lock = (W/'direct-fixture.lock').open('a')
    fcntl.flock(lock.fileno(), fcntl.LOCK_EX|fcntl.LOCK_NB)
    build = json.loads((B/'status.json').read_text())
    assert build['status'] == 'MATCHED_BUILD_PASS_RUNTIME_NOT_RUN'
    assert build['builds']['baseline']['config_sha256'] == build['builds']['candidate']['config_sha256']
    frozen = json.loads((D/args.workload/'manifest.json').read_text())
    for stem in ('guest', 'business'):
        assert sha(D/args.workload/(stem+'.ext4')) == frozen[stem+'_sha256']
    root = D/args.workload/args.stamp
    root.mkdir(exist_ok=False)
    order = [(1, 'baseline', 2), (1, 'candidate', 2)] if args.mode == 'smoke' else [
        (r, v, n) for r in (1, 2, 3) for n in ((1, 12) if r%2 else (12, 1))
        for v in (('baseline', 'candidate') if r%2 else ('candidate', 'baseline'))]
    if args.mode == 'formal':
        plan = json.loads(Path(args.formal_plan).read_text())
        assert plan['workload'] == args.workload and 5 <= plan['blocks'] <= 12
        order = plan['order']
        assert len(order) == plan['blocks']*4
        assert len({tuple(x) for x in order}) == len(order)
        assert all(n in (1,12) and v in ('baseline','candidate') and 1 <= r <= plan['blocks'] for r,v,n in order)
    if args.mode == 'diagnostic':
        order = [(1,'baseline',1),(1,'candidate',1),(1,'baseline',12),(1,'candidate',12)]
    if args.mode == 'baseline-diagnostic':
        order = [(1,'baseline',1),(1,'baseline',12)]
    (root/'plan.json').write_text(json.dumps(dict(mode=args.mode, order=order, frozen=frozen,
        metric='last action end minus first action start; target slot zero',
        scope='52-vCPU single shared guest; fixed 52GiB and host node0; not bare-metal NUMA'), indent=2))
    records = []
    try:
        for r, v, n in order:
            record = execute(root, args.workload, v, n, r, build)
            records.append(record)
            (root/'status.json').write_text(json.dumps(dict(status='RUNNING', runs=records), indent=2))
            assert record['status'] == 'PASS', 'state rejected'
    finally:
        ok = len(records) == len(order) and all(r['status'] == 'PASS' for r in records)
        (root/'status.json').write_text(json.dumps(dict(status='PASS' if ok else 'FAIL', runs=records), indent=2))


if __name__ == '__main__':
    main()
