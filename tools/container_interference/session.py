#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Administrator-only, single-session controller. No periodic collection.

The standard-library controller never loads BPF. Each C worker owns a fresh
capture. An inventory must be durably acknowledged before probes can activate.
The separate control socket stays usable if report I/O or a worker stalls.
"""
import argparse
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import secrets
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

VERSION = 1
MAX_PACKET = 8192
MAX_ROOTS = 256
MAX_HISTORY = 256
PREPARE_NS = 10_000_000_000
CLEANUP_NS = 5_000_000_000
VERIFY_NS = 2_000_000_000
WINDOW_MS = 2000
HERE = Path(__file__).resolve().parent


def now():
    return time.monotonic_ns()


def reaped_child_cpu_ns():
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return round((usage.ru_utime + usage.ru_stime) * 1e9)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def host_admin(pid=None):
    pid = pid or os.getpid()
    return (os.stat('/proc/%d/ns/user' % pid).st_ino == os.stat('/proc/1/ns/user').st_ino
            and os.stat('/proc/%d/ns/cgroup' % pid).st_ino == os.stat('/proc/1/ns/cgroup').st_ino)


def atomic(path, value):
    data = encoded(value)
    temp = path.with_suffix('.new')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temp.exists():
            temp.unlink()


def validate(request):
    if not isinstance(request, dict) or type(request.get('version')) is not int or request.get('version') != VERSION:
        raise ValueError('unsupported protocol')
    op = request.get('op')
    fields = {'register': {'path'}, 'unregister': {'target'}, 'status': {'session'},
              'report': {'session'}, 'cancel': {'session'}, 'stop': set(), 'recover': set(),
              'start': {'nonce', 'collector', 'targets', 'window_ms', 'inject'}}
    if op not in fields or set(request) - fields[op] - {'version', 'op'}:
        raise ValueError('unknown command or field')
    if op == 'start':
        if request.get('collector') not in ('ip', 'owner'):
            raise ValueError('collector must be ip or owner')
        targets = request.get('targets')
        if (not isinstance(targets, list) or not 1 <= len(targets) <= 2
                or not all(isinstance(t, str) and len(t) <= 48 for t in targets)
                or len(set(targets)) != len(targets)):
            raise ValueError('one or two distinct targets required')
        if type(request.get('window_ms', WINDOW_MS)) is not int or not 100 <= request.get('window_ms', WINDOW_MS) <= 10000:
            raise ValueError('window outside 100..10000 ms')
        nonce = request.get('nonce', '')
        if not isinstance(nonce, str) or not 1 <= len(nonce) <= 64 or not nonce.isascii() or not nonce.isalnum():
            raise ValueError('bounded alphanumeric idempotency nonce required')
        if request.get('inject', 'none') not in ('none', 'after_prepare'):
            raise ValueError('unknown injection')
    return request


class Controller:
    def __init__(self, args):
        if os.geteuid() or not host_admin():
            raise PermissionError('initial namespace administrator required')
        self.args = args
        self.directory = Path(args.directory).resolve()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        st = self.directory.stat()
        if st.st_uid or st.st_mode & 0o077:
            raise PermissionError('state directory must be root-owned mode 0700')
        self.lock = os.open('/run/cis-profile.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.selector = selectors.DefaultSelector()
        self.wake_r, self.wake_w = socket.socketpair()
        self.wake_r.setblocking(False)
        self.wake_w.setblocking(False)
        self.selector.register(self.wake_r, selectors.EVENT_READ, 'wake')
        signal.set_wakeup_fd(self.wake_w.fileno())
        self.roots, self.history = {}, {}
        self.active = None
        self.faulted = False
        self.stopping = False
        self.boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        self.serial = secrets.randbits(48)
        self.manifest = {'protocol': VERSION, 'boot_id': self.boot,
                         'controller_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                         'worker_sha256': hashlib.sha256(Path(args.worker).read_bytes()).hexdigest(),
                         'bpf_sha256': hashlib.sha256(Path(args.bpf).read_bytes()).hexdigest(),
                         'memory_total_complete': False}
        # Unfinished journals are not guessed safe from a recycled PID or path.
        for file in self.directory.glob('*.json'):
            saved = json.loads(file.read_text())
            if 'session_id' in saved:
                self.history[saved['session_id']] = saved
            if saved.get('state') != 'IDLE':
                self.faulted = True
        self.global_journal = Path('/run/cis-profile-active.json')
        if self.global_journal.exists() and json.loads(self.global_journal.read_text()).get('state') != 'IDLE':
            self.faulted = True
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        if Path(args.socket).exists():
            if not stat.S_ISSOCK(os.lstat(args.socket).st_mode):
                raise PermissionError('refuse non-socket endpoint')
            os.unlink(args.socket)  # protected by the unique host controller lock
        self.server.bind(args.socket)
        os.chmod(args.socket, 0o600)
        self.server.listen(8)
        self.server.setblocking(False)
        self.selector.register(self.server, selectors.EVENT_READ, 'server')

    def persist(self, session):
        atomic(self.directory / ('%s.json' % session['session_id']), session)
        atomic(self.global_journal, {'state': session['state'], 'session_id': session['session_id'],
                                    'boot_id': self.boot, 'directory': str(self.directory)})

    def register(self, path):
        if len(self.roots) >= MAX_ROOTS:
            raise OSError(errno.ENOSPC, 'registration capacity')
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            actual = os.readlink('/proc/self/fd/%d' % fd)
            info = os.fstat(fd)
            if (not actual.startswith('/sys/fs/cgroup/') or actual.endswith(' (deleted)')
                    or info.st_dev != os.stat('/sys/fs/cgroup').st_dev):
                raise ValueError('host cgroup-v2 descendants only')
            check = os.open('cgroup.events', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(check)
            for root in self.roots.values():
                if actual == root['path'] or actual.startswith(root['path'] + '/') or root['path'].startswith(actual + '/'):
                    raise ValueError('overlapping registration')
            self.serial += 1
            key = '%d:%d' % (info.st_ino, self.serial)
            self.roots[key] = {'fd': fd, 'path': actual, 'id': info.st_ino, 'generation': self.serial}
            return {'target': key}
        except BaseException:
            os.close(fd)
            raise

    def start(self, request):
        fingerprint = hashlib.sha256(encoded(request)).hexdigest()
        for saved in self.history.values():
            if saved['nonce'] == request['nonce']:
                if saved['request_hash'] != fingerprint:
                    raise ValueError('nonce reused with different request')
                return saved
        if self.faulted or self.active:
            raise OSError(errno.EBUSY, 'FAULTED or active/draining session')
        if len(self.history) >= MAX_HISTORY:
            raise OSError(errno.ENOSPC, 'controller history full; restart when safely IDLE')
        roots = [self.roots[key] for key in request['targets']]
        for root in roots:
            if os.readlink('/proc/self/fd/%d' % root['fd']) != root['path']:
                raise ValueError('target deleted or renamed')
        if request.get('inject', 'none') != 'none' and not self.args.test_faults:
            raise PermissionError('fault injection disabled')
        sid = str(secrets.randbits(63) or 1)
        record = dict(self.manifest, session_id=sid, nonce=request['nonce'], request_hash=fingerprint,
                      state='PREPARE', result=None, requested_ns=now(), collector=request['collector'],
                      window_ms=request.get('window_ms', WINDOW_MS), targets=request['targets'],
                      inventory=None, receipt=None, cancellation_requested=False,
                      transitions=[{'state': 'ADMIT', 'time_ns': now()}, {'state': 'PREPARE', 'time_ns': now()}])
        record['config_hash'] = hashlib.sha256(encoded({'request': request, 'manifest': self.manifest})).hexdigest()
        self.persist(record)
        self.history[sid] = record
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        output = os.open(self.directory / (sid + '.jsonl'), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        errors = os.open(self.directory / (sid + '.stderr'), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            command = [self.args.worker, str(child.fileno()), str(output), sid, request['collector'],
                       str(record['window_ms']), self.args.bpf, request.get('inject', 'none')]
            command += ['%d:%d:%d' % (root['fd'], root['id'], root['generation']) for root in roots]
            child_process = subprocess.Popen(command, pass_fds=(child.fileno(), output, *[r['fd'] for r in roots]),
                                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=errors)
        except BaseException:
            record.update(state='FAULTED', result='FAILED', reason='SPAWN')
            self.faulted = True
            self.persist(record)
            parent.close()
            raise
        finally:
            child.close()
            os.close(output)
            os.close(errors)
        pidfd = os.pidfd_open(child_process.pid)
        parent.setblocking(False)
        self.active = {'record': record, 'process': child_process, 'channel': parent,
                       'pidfd': pidfd, 'deadline': now() + PREPARE_NS, 'killed': False,
                       'controller_cpu_begin': time.process_time_ns(),
                       'child_cpu_begin': reaped_child_cpu_ns(), 'memory_peak': 0}
        self.selector.register(parent, selectors.EVENT_READ, 'worker')
        self.selector.register(pidfd, selectors.EVENT_READ, 'exit')
        record['worker_pid'] = child_process.pid
        record['worker_start_ticks'] = Path('/proc/%d/stat' % child_process.pid).read_text().rsplit(')', 1)[1].split()[19]
        self.persist(record)
        return record

    def cancel(self, sid):
        record = self.history[sid]
        if not self.active or self.active['record'] is not record:
            return record
        if not record['cancellation_requested']:
            record['cancellation_requested'] = True
            try:
                self.active['channel'].send(b'CANCEL')
            except OSError:
                pass
            signal.pidfd_send_signal(self.active['pidfd'], signal.SIGTERM)
            self.active['deadline'] = now() + CLEANUP_NS
        return record

    def request(self, req):
        validate(req)
        op = req['op']
        if op == 'register':
            return self.register(req['path'])
        if op == 'unregister':
            key = req['target']
            if self.active and key in self.active['record']['targets']:
                self.cancel(self.active['record']['session_id'])
                raise OSError(errno.EBUSY, 'drain before unregister')
            os.close(self.roots.pop(key)['fd'])
            return {'removed': key}
        if op == 'start':
            return self.start(req)
        if op == 'recover':
            if self.active:
                raise OSError(errno.EBUSY, 'worker not reaped')
            if not self.global_journal.exists():
                raise ValueError('no journal to recover')
            pointer = json.loads(self.global_journal.read_text())
            path = Path(pointer['directory']) / (pointer['session_id'] + '.json')
            record = json.loads(path.read_text())
            if record['boot_id'] != self.boot:
                raise ValueError('different boot requires explicit offline audit')
            if Path('/proc/%s' % record.get('worker_pid', 0)).exists():
                raise OSError(errno.EBUSY, 'recorded PID exists; do not guess or kill reused PID')
            inventory = record.get('inventory') or {'maps': [], 'programs': []}
            commands = ['m:%d' % v for v in inventory['maps']] + ['p:%d' % v for v in inventory['programs']]
            checked = subprocess.run([self.args.residue] + commands, capture_output=True, timeout=1)
            if checked.returncode:
                raise OSError(errno.EBUSY, 'object inventory absent not proved')
            record.update(state='IDLE', result='FAILED', recovery='administrator_checked_pid_absent_and_inventory_absent')
            atomic(path, record)
            atomic(self.global_journal, dict(pointer, state='IDLE'))
            self.history[record['session_id']] = record
            self.faulted = False
            return record
        if op == 'cancel':
            return self.cancel(req['session'])
        if op in ('status', 'report'):
            if req.get('session'):
                return self.history[req['session']]
            return {'state': 'FAULTED' if self.faulted else self.active['record']['state'] if self.active else 'IDLE',
                    'roots': len(self.roots), 'sessions': list(self.history), 'metrics_scans': 0, 'psi_triggers': 0}
        if op == 'stop':
            self.stopping = True
            if self.active:
                self.cancel(self.active['record']['session_id'])
            return {'stopping': True}

    def serve_one(self):
        connection, _ = self.server.accept()
        with connection:
            connection.settimeout(.05)
            try:
                pid, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if uid or not host_admin(pid):
                    raise PermissionError('host administrator required')
                data, ancillary, flags, _ = connection.recvmsg(MAX_PACKET, socket.CMSG_SPACE(16))
                # Never accept passed descriptors or silently truncate messages.
                for level, kind, value in ancillary:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        for fd in struct.unpack('%di' % (len(value)//4), value):
                            os.close(fd)
                if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or ancillary:
                    raise ValueError('oversize packet or unexpected descriptors')
                result = {'ok': True, 'data': self.request(json.loads(data))}
            except (OSError, ValueError, KeyError, TypeError) as error:
                result = {'ok': False, 'error': str(error)}
            try:
                connection.send(encoded(result))
            except OSError:
                pass

    def worker_event(self):
        active = self.active
        if not active:
            return
        channel, record = active['channel'], active['record']
        try:
            data = channel.recv(MAX_PACKET)
        except BlockingIOError:
            return
        except ConnectionResetError:
            data = b''
        if not data:
            try:
                self.selector.unregister(channel)
            except KeyError:
                pass
            return
        message = json.loads(data)
        state = message['state']
        if state not in ('ARMED', 'CAPTURING', 'DRAIN', 'VERIFY'):
            raise ValueError('invalid worker state')
        legal = {'PREPARE': {'ARMED', 'DRAIN'}, 'ARMED': {'CAPTURING', 'DRAIN'},
                 'CAPTURING': {'DRAIN'}, 'DRAIN': {'VERIFY'}, 'FAULTED': {'DRAIN', 'VERIFY'}}
        if state not in legal.get(record['state'], set()):
            raise ValueError('invalid worker transition')
        record['state'] = state
        record['transitions'].append({'state': state, 'time_ns': now()})
        if state == 'ARMED':
            record['inventory'] = message['inventory']
            self.persist(record)
            try:
                channel.send(b'CANCEL' if record['cancellation_requested'] else b'ARM')
            except (BrokenPipeError, ConnectionResetError):
                record['control_closed_before_arm'] = True
            active['deadline'] = now() + record['window_ms']*1_000_000 + CLEANUP_NS
        elif state == 'CAPTURING':
            record['window'] = message
            active['deadline'] = message['end_ns'] + CLEANUP_NS
        elif state == 'DRAIN':
            active['deadline'] = now() + CLEANUP_NS
        elif state == 'VERIFY':
            record['receipt'] = message
            active['deadline'] = now() + VERIFY_NS

    def finish(self):
        active, record = self.active, self.active['record']
        # Consume every bounded control packet before judging worker exit.
        for _ in range(8):
            try:
                if not select_ready(active['channel']):
                    break
                self.worker_event()
            except (KeyError, OSError):
                break
        code = active['process'].wait()
        inventory = record['inventory']
        commands = []
        if inventory:
            commands = ['m:%d' % v for v in inventory['maps']] + ['p:%d' % v for v in inventory['programs']]
        verified = False
        # Kernel object IDs may survive close briefly. Never delete another tool's resources.
        check_end = now() + VERIFY_NS
        if commands:
            while now() < check_end:
                checked = subprocess.run([self.args.residue] + commands, capture_output=True, timeout=1)
                if checked.returncode == 0:
                    verified = True
                    break
                if checked.returncode != 1:
                    break
                time.sleep(.02)
        elif not record.get('window'):
            # No ARM acknowledgment without a durably recorded inventory.
            verified = True
        receipt = record['receipt'] or {}
        record.update(exit_code=code, stopped_ns=now(), objects_absent=verified,
                      controller_cpu_ns=time.process_time_ns()-active['controller_cpu_begin'],
                      combined_rss_peak_bytes=active['memory_peak'],
                      reaped_children_cpu_ns=reaped_child_cpu_ns()-active['child_cpu_begin'],
                      worker_cpu_accounting='receipt is subset of reaped children, do not sum twice; kernel async residual unknown',
                      async_reclamation_complete=False)
        record['observer_process_cpu_ns'] = record['controller_cpu_ns'] + record['reaped_children_cpu_ns']
        safe = verified and not receipt.get('stop_error') and not active['killed']
        record['state'] = 'IDLE' if safe else 'FAULTED'
        record['result'] = receipt.get('result', 'FAILED') if safe else 'FAILED'
        if record['cancellation_requested'] and safe:
            record['result'] = 'CANCELLED'
        if (not receipt and not record['cancellation_requested']) or active['killed']:
            record['result'] = 'FAILED'
        record['transitions'].append({'state': record['state'], 'time_ns': now()})
        self.faulted |= not safe
        for fd in (active['channel'], active['pidfd']):
            try:
                self.selector.unregister(fd)
            except KeyError:
                pass
        active['channel'].close()
        os.close(active['pidfd'])
        self.active = None
        self.persist(record)

    def run(self):
        while not self.stopping or self.active:
            timeout = min(.1, max(0, (self.active['deadline']-now())/1e9)) if self.active else None
            for key, _ in self.selector.select(timeout):
                if key.data == 'server':
                    self.serve_one()
                elif key.data == 'worker' and self.active:
                    self.worker_event()
                elif key.data == 'exit' and self.active:
                    self.finish()
                elif key.data == 'wake':
                    self.wake_r.recv(4096)
            if self.active:
                try:
                    pages = sum(int(Path('/proc/%d/statm' % pid).read_text().split()[1])
                                for pid in (os.getpid(), self.active['process'].pid))
                    rss = pages * os.sysconf('SC_PAGE_SIZE')
                    self.active['memory_peak'] = max(rss, self.active['memory_peak'])
                    if rss > 64*1024*1024:
                        self.cancel(self.active['record']['session_id'])
                        self.active['record']['budget_reason'] = 'COMBINED_RSS_LIMIT_incomplete_kernel_accounting'
                except (FileNotFoundError, ProcessLookupError):
                    pass
            if self.active and now() >= self.active['deadline']:
                signal.pidfd_send_signal(self.active['pidfd'], signal.SIGKILL)
                self.active['killed'] = True
                self.active['deadline'] = now() + CLEANUP_NS
                self.faulted = True
                self.active['record']['state'] = 'FAULTED'
                self.persist(self.active['record'])
        for root in self.roots.values():
            os.close(root['fd'])
        self.server.close()
        os.unlink(self.args.socket)
        signal.set_wakeup_fd(-1)
        self.wake_r.close()
        self.wake_w.close()
        os.close(self.lock)


def select_ready(channel):
    import select
    return bool(select.select([channel], [], [], 0)[0])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', default='/run/cis-profile.sock')
    parser.add_argument('--directory', default='/run/cis-profile')
    parser.add_argument('--worker', default=str(HERE/'session-worker'))
    parser.add_argument('--bpf', default=str(HERE/'bpf/cis.bpf.o'))
    parser.add_argument('--residue', default=str(HERE/'session-residue'))
    parser.add_argument('--test-faults', action='store_true')
    parser.add_argument('command', choices=('daemon', 'request'))
    parser.add_argument('json', nargs='?')
    args = parser.parse_args()
    if args.command == 'request':
        request = validate(json.loads(args.json))
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
            client.settimeout(15)
            client.connect(args.socket)
            client.send(encoded(request))
            result = json.loads(client.recv(MAX_PACKET))
            print(json.dumps(result))
            return 0 if result['ok'] else 1
    controller = Controller(args)
    def stop(signum, frame):
        controller.stopping = True
        if controller.active:
            controller.cancel(controller.active['record']['session_id'])
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    controller.run()
    return 0


if __name__ == '__main__':
    sys.exit(main())
