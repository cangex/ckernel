#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Administrator-only bounded sessions with receipt-gated periodic surveys.

The standard-library controller never loads BPF. Each C worker owns a fresh
capture. An inventory must be durably acknowledged before probes can activate.
The separate control socket stays usable if report I/O or a worker stalls.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import copy
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
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
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
from periodic_plan import capacity, digest, require_acceptance, validate_plan
from process_budget import ProcessBudget
from child_usage import ChildProcesses, reaped_cpu_ns as reaped_child_cpu_ns
from schedule import Schedule
import survey


def now():
    return time.monotonic_ns()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def compact_record(record):
    return {key: value for key, value in record.items()
            if key not in ('boundary_before', 'boundary_after', 'survey', 'source_identity')}


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
              'start': {'nonce', 'nonce_epoch', 'collector', 'targets', 'window_ms', 'inject'},
              'schedule_configure': {'plan'}, 'schedule_enable': set(),
              'schedule_pause': set(), 'schedule_status': {'offset'},
              'survey_epoch': set(), 'survey_report': {'target'}}
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
        if 'nonce_epoch' in request and (not isinstance(request['nonce_epoch'], str) or not re.fullmatch('[0-9a-f]{32}', request['nonce_epoch'])):
            raise ValueError('invalid nonce epoch')
    if op == 'schedule_configure':
        validate_plan(request.get('plan'))
    if op == 'schedule_status' and (type(request.get('offset', 0)) is not int or not 0 <= request.get('offset', 0) <= MAX_ROOTS):
        raise ValueError('invalid status offset')
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
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='cis-io')
        self.io = None
        self.children = ChildProcesses()
        self.schedule = None
        self.surveys = {}
        self.references = {}
        self.boundary_reads = 0
        self.survey_epoch = 0
        self.nonce_epoch = secrets.token_hex(16)
        self.roots, self.history = {}, {}
        self.active = None
        self.faulted = False
        self.stopping = False
        self.boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        self.serial = secrets.randbits(48)
        self.manifest = {'protocol': VERSION, 'boot_id': self.boot,
                         'controller_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                         'worker_sha256': hashlib.sha256(Path(args.worker).read_bytes()).hexdigest(),
                         'residue_sha256': hashlib.sha256(Path(args.residue).read_bytes()).hexdigest(),
                         'bpf_sha256': hashlib.sha256(Path(args.bpf).read_bytes()).hexdigest(),
                         'support_sha256': digest({name: hashlib.sha256((HERE/name).read_bytes()).hexdigest()
                            for name in ('schedule.py', 'periodic_plan.py', 'survey.py', 'process_budget.py', 'child_usage.py')}),
                         'kernel_release': os.uname().release,
                         'kernel_notes_sha256': hashlib.sha256(Path('/sys/kernel/notes').read_bytes()).hexdigest(),
                         'memory_total_complete': False}
        # Unfinished journals are not guessed safe from a recycled PID or path.
        for file in self.directory.glob('*.json'):
            if not file.stem.isdecimal():
                continue
            saved = json.loads(file.read_text())
            if 'session_id' in saved:
                self.history[saved['session_id']] = saved
            if saved.get('state') != 'IDLE':
                self.faulted = True
        if len(self.history) > MAX_HISTORY:
            raise OSError(errno.ENOSPC, 'bounded history exceeded; offline audit required')
        self.metadata = self.directory / 'periodic'
        self.metadata.mkdir(mode=0o700, exist_ok=True)
        if self.metadata.is_symlink() or self.metadata.stat().st_uid or self.metadata.stat().st_mode & 0o077:
            raise PermissionError('private periodic metadata directory required')
        meta_file = self.metadata / 'state.json'
        if meta_file.exists():
            saved = json.loads(meta_file.read_text())
            self.schedule = Schedule(saved['plan'], now) if saved.get('plan') else None
            if self.schedule and saved.get('boot_id') == self.boot:
                self.schedule.last_admit_ns = saved.get('last_admit_ns')
            # Restart is always paused and roots must be re-registered. No PID/cgroup guessing.
            self.survey_epoch = saved.get('survey_epoch', 0) + 1
        self.save_metadata()
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

    def save_metadata(self):
        atomic(self.metadata/'state.json', dict(plan=self.schedule.plan if self.schedule else None,
               survey_epoch=self.survey_epoch, nonce_epoch=self.nonce_epoch,
               boot_id=self.boot, last_admit_ns=self.schedule.last_admit_ns if self.schedule else None,
               restart_policy='paused; explicit register and admission required'))

    def submit_io(self, name, function, callback):
        if self.io:
            raise RuntimeError('bounded IO slot occupied')
        future = self.executor.submit(function)
        self.io = (name, future, callback)
        def wake(_):
            try:
                self.wake_w.send(b'i')
            except OSError:
                pass
        future.add_done_callback(wake)

    def helper(self, command):
        child = self.children.spawn(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            return self.children.wait(child, timeout=1)
        except subprocess.TimeoutExpired:
            self.children.kill(child)
            self.children.wait(child)
            return -1

    def process_cpu(self):
        return self.children.cpu_ns()

    def pump_io(self):
        if self.io and self.io[1].done():
            name, future, callback = self.io
            self.io = None
            try:
                callback(future.result())
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                self.faulted = True
                if self.schedule:
                    self.schedule.pause()
                if self.active:
                    self.active['record']['io_error'] = name + ': ' + str(error)
                    self.cancel(self.active['record']['session_id'])
                    if self.children.poll(self.active['process']) is not None:
                        self.release_active(faulted=True)
        if self.io or not self.active:
            return
        active = self.active
        if active.get('exited'):
            record = active['record']
            record['state'] = 'VERIFY'
            active['deadline'] = now()+CLEANUP_NS
            snapshot = copy.deepcopy(record)
            roots = {key: dict(self.roots[key]) for key in record['targets']}
            self.submit_io('verify_and_survey', lambda: self.verify_result(snapshot, roots), self.finish_verified)
        elif active.pop('arm_pending', False):
            snapshot = copy.deepcopy(active['record'])
            def journal():
                self.persist(snapshot)
                return {key: survey.snapshot(self.roots[key]) for key in snapshot['targets']} if self.schedule else None
            self.submit_io('arm_inventory', journal, self.arm_after_journal)

    def arm_after_journal(self, boundary):
        if not self.active or self.active.get('exited'):
            return
        active = self.active
        reason = active['budget'].check(self.process_cpu(), 'ARMED')
        if reason:
            active['record']['budget_reason'] = reason
            self.cancel(active['record']['session_id'])
        if boundary is not None:
            active['record']['boundary_before'] = boundary
            self.boundary_reads += len(boundary)
        try:
            active['channel'].send(b'CANCEL' if active['record']['cancellation_requested'] else b'ARM')
        except (BrokenPipeError, ConnectionResetError):
            active['record']['control_closed_before_arm'] = True
        active['deadline'] = now()+active['record']['window_ms']*1_000_000+CLEANUP_NS

    def storage_admit(self):
        if not self.schedule:
            return
        used = sum(path.stat().st_size for path in self.directory.iterdir() if path.is_file())
        fs = os.statvfs(self.directory)
        if used+20*2**20 > self.schedule.plan['disk_bytes'] or fs.f_bavail*fs.f_frsize < 32*2**20:
            raise OSError(errno.ENOSPC, 'profile disk budget or free-space reserve')

    def retire_history(self):
        if not self.schedule:
            return
        keep = self.schedule.plan['retain_sessions']
        sizes = {path.name: path.stat().st_size for path in self.directory.iterdir() if path.is_file()}
        used = sum(sizes.values())
        pressure = used+20*2**20 > self.schedule.plan['disk_bytes']
        if len(self.history) <= keep and len(self.history) < MAX_HISTORY and not pressure:
            return
        cutoff = now()-self.schedule.plan['retain_seconds']*1_000_000_000
        eligible = [record for record in self.history.values()
                    if record.get('retention_managed') and record.get('state') == 'IDLE'
                    and record.get('objects_absent') is True and record.get('boot_id') == self.boot
                    and record.get('stopped_ns', now()) < cutoff]
        eligible.sort(key=lambda value: value['stopped_ns'])
        count = len(self.history)
        selected = []
        for record in eligible:
            if count <= keep and count < MAX_HISTORY and used+20*2**20 <= self.schedule.plan['disk_bytes']:
                break
            selected.append(record)
            count -= 1
            used -= sum(sizes.get(record['session_id']+suffix, 0) for suffix in ('.json', '.jsonl', '.stderr'))
        eligible = selected
        if not eligible:
            return
        # Commit a new nonce epoch BEFORE retiring records. Old requests are rejected,
        # not silently executed again after an idempotency record has expired.
        self.nonce_epoch = secrets.token_hex(16)
        self.save_metadata()
        for record in eligible:
            sid = record['session_id']
            for suffix in ('.jsonl', '.stderr', '.json'):
                path = self.directory/(sid+suffix)
                if path.is_symlink():
                    raise PermissionError('refuse symlink in owned session retention')
                path.unlink(missing_ok=True)
            del self.history[sid]

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
            if self.schedule:
                self.schedule.add(key)
            self.roots[key] = {'fd': fd, 'path': actual, 'id': info.st_ino, 'generation': self.serial}
            return {'target': key}
        except BaseException:
            os.close(fd)
            raise

    def start(self, request, planned=None):
        if self.schedule and request.get('nonce_epoch') != self.nonce_epoch:
            raise ValueError('nonce epoch expired; query status before a new request')
        fingerprint = hashlib.sha256(encoded(request)).hexdigest()
        for saved in self.history.values():
            if saved['nonce'] == request['nonce'] and saved.get('nonce_epoch') == request.get('nonce_epoch'):
                if saved['request_hash'] != fingerprint:
                    raise ValueError('nonce reused with different request')
                return saved
        if self.faulted or self.active:
            raise OSError(errno.EBUSY, 'FAULTED or active/draining session')
        self.retire_history()
        if self.schedule and request.get('nonce_epoch') != self.nonce_epoch:
            raise ValueError('history rotated; nonce epoch expired')
        self.storage_admit()
        if len(self.history) >= MAX_HISTORY:
            raise OSError(errno.ENOSPC, 'controller history full; restart when safely IDLE')
        roots = [self.roots[key] for key in request['targets']]
        for root in roots:
            if os.readlink('/proc/self/fd/%d' % root['fd']) != root['path']:
                raise ValueError('target deleted or renamed')
        if request.get('inject', 'none') != 'none' and not self.args.test_faults:
            raise PermissionError('fault injection disabled')
        if self.schedule:
            if request.get('window_ms', WINDOW_MS) > self.schedule.plan['window_ms']:
                raise ValueError('manual window exceeds shared host budget')
            self.schedule.admit(request['targets'], manual=planned is None)
            self.save_metadata()
        cpu_begin = self.process_cpu()
        sid = str(secrets.randbits(63) or 1)
        record = dict(self.manifest, session_id=sid, nonce=request['nonce'], request_hash=fingerprint,
                      state='PREPARE', result=None, requested_ns=now(), collector=request['collector'],
                      finalized=False,
                      window_ms=request.get('window_ms', WINDOW_MS), targets=request['targets'],
                      inventory=None, receipt=None, cancellation_requested=False,
                      nonce_epoch=request.get('nonce_epoch'), retention_managed=bool(self.schedule),
                      survey_epoch=self.survey_epoch, scheduled=planned,
                      root_identities={key: {field: self.roots[key][field] for field in ('id', 'generation')}
                                       for key in request['targets']},
                      source_identity={key: self.manifest[key] for key in ('controller_sha256', 'worker_sha256',
                                       'residue_sha256', 'bpf_sha256', 'support_sha256', 'kernel_release', 'kernel_notes_sha256')},
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
            child_process = self.children.spawn(command, pass_fds=(child.fileno(), output, *[r['fd'] for r in roots]),
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
                       'child_cpu_begin': reaped_child_cpu_ns(), 'memory_peak': 0, 'process_cpu_begin': cpu_begin}
        self.active['budget'] = ProcessBudget(cpu_begin, record['window_ms'], self.schedule.plan if self.schedule else None)
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
        if self.active.get('publishing'):
            # Producers have stopped; do not interrupt the durable cleanup receipt.
            return record
        if not record['cancellation_requested']:
            record['cancellation_requested'] = True
            try:
                self.active['channel'].send(b'CANCEL')
            except OSError:
                pass
            if self.children.poll(self.active['process']) is None:
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
            if self.schedule:
                self.schedule.remove(key)
            self.surveys.pop(key, None)
            self.references.pop(key, None)
            return {'removed': key}
        if op == 'start':
            return compact_record(self.start(req))
        if op == 'schedule_configure':
            if self.active or self.faulted or (self.schedule and self.schedule.enabled):
                raise OSError(errno.EBUSY, 'configure only while safely paused')
            proposed = Schedule(req['plan'], now)
            for key in self.roots:
                proposed.add(key)
            if self.schedule:
                proposed.last_admit_ns = self.schedule.last_admit_ns
            self.schedule = proposed
            self.nonce_epoch = secrets.token_hex(16)
            self.save_metadata()
            return dict(plan=proposed.plan, capacity=capacity(proposed.plan, len(self.roots)), nonce_epoch=self.nonce_epoch)
        if op == 'schedule_enable':
            if not self.schedule or self.faulted or self.active:
                raise OSError(errno.EBUSY, 'configure and clear faults before enabling')
            path = getattr(self.args, 'p1_acceptance', None)
            if not path:
                raise ValueError('P1 acceptance missing; periodic collection stays disabled')
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid or info.st_mode & 0o077 or info.st_size > 65536:
                    raise PermissionError('P1 receipt must be bounded, private and root-owned')
                evidence = json.loads(os.read(fd, 65537))
            finally:
                os.close(fd)
            receipt = require_acceptance(evidence, self.manifest)
            self.schedule.enable()
            return dict(enabled=True, admission_sha256=receipt, next_ns=self.schedule.next_ns)
        if op == 'schedule_pause':
            if self.schedule:
                self.schedule.pause()
            return dict(paused=True, active_session=self.active['record']['session_id'] if self.active else None)
        if op == 'schedule_status':
            if not self.schedule:
                return dict(configured=False)
            status = self.schedule.status()
            offset = req.get('offset', 0)
            keys = sorted(status['roots'])[offset:offset+16]
            status['roots'] = {key: status['roots'][key] for key in keys}
            status['next_offset'] = offset+len(keys) if offset+len(keys) < len(self.roots) else None
            status['recent'] = status['recent'][-8:]
            return status
        if op == 'survey_epoch':
            if self.active:
                raise OSError(errno.EBUSY, 'finish current epoch session first')
            self.survey_epoch += 1
            self.surveys.clear()
            self.references.clear()
            if self.schedule:
                for value in self.schedule.roots.values():
                    value['valid_ns'] = None
                    value['candidate'] = False
            self.save_metadata()
            return dict(survey_epoch=self.survey_epoch)
        if op == 'survey_report':
            return self.surveys.get(req['target'], dict(status='NOT_OBSERVED'))
        if op == 'recover':
            if self.active or self.io:
                raise OSError(errno.EBUSY, 'worker not reaped')
            if not self.global_journal.exists():
                raise ValueError('no journal to recover')
            pointer = json.loads(self.global_journal.read_text())
            if any(value.get('state') != 'IDLE' and sid != pointer['session_id']
                   for sid, value in self.history.items()):
                raise OSError(errno.EBUSY, 'multiple unresolved journals require offline inventory audit')
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
                record = self.history[req['session']]
                return compact_record(record) if op == 'status' else record
            return {'state': 'FAULTED' if self.faulted else self.active['record']['state'] if self.active else 'IDLE',
                    'roots': len(self.roots), 'sessions': list(self.history), 'continuous_metrics_scans': 0,
                    'boundary_root_reads': self.boundary_reads, 'psi_triggers': 0,
                    'nonce_epoch': self.nonce_epoch, 'periodic_enabled': bool(self.schedule and self.schedule.enabled)}
        if op == 'stop':
            self.stopping = True
            if self.schedule:
                self.schedule.pause()
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
                packet = encoded(result)
                if len(packet) > MAX_PACKET:
                    packet = encoded(dict(ok=False, error='response exceeds packet limit; use paged status or local report'))
                connection.send(packet)
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
        # Close the old phase before pump_io can start verification helpers.
        # Otherwise their CPU can be charged to a just-finished capture phase.
        reason = active['budget'].check(self.process_cpu(), state)
        if reason:
            record['budget_reason'] = reason
            self.cancel(record['session_id'])
        if state == 'ARMED':
            record['inventory'] = message['inventory']
            active['arm_pending'] = True
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
        code = self.children.poll(active['process'])
        if code is None:
            return
        record['exit_code'] = code
        active['exited'] = True
        self.selector.unregister(active['pidfd'])
        try:
            self.selector.unregister(active['channel'])
        except KeyError:
            pass

    def verify_result(self, record, roots):
        inventory = record['inventory']
        commands = []
        if inventory:
            commands = ['m:%d' % v for v in inventory['maps']] + ['p:%d' % v for v in inventory['programs']]
        verified = False
        # Kernel object IDs may survive close briefly. Never delete another tool's resources.
        check_end = now() + VERIFY_NS
        if commands:
            while now() < check_end:
                checked = self.helper([self.args.residue] + commands)
                if checked == 0:
                    verified = True
                    break
                if checked != 1:
                    break
                time.sleep(.02)
        elif not record.get('window'):
            # No ARM acknowledgment without a durably recorded inventory.
            verified = True
        after = {key: survey.snapshot(root) for key, root in roots.items()} if self.schedule else None
        return dict(verified=verified, after=after)

    def finish_verified(self, verification):
        active, record = self.active, self.active['record']
        receipt = record['receipt'] or {}
        verified = verification['verified']
        record.update(stopped_ns=now(), objects_absent=verified,
                      controller_cpu_ns=time.process_time_ns()-active['controller_cpu_begin'],
                      combined_rss_peak_bytes=active['memory_peak'],
                      reaped_children_cpu_ns=reaped_child_cpu_ns()-active['child_cpu_begin'],
                      worker_cpu_accounting='receipt is subset of reaped children, do not sum twice; kernel async residual unknown',
                      async_reclamation_complete=False)
        record['observer_process_cpu_ns'] = record['controller_cpu_ns'] + record['reaped_children_cpu_ns']
        safe = verified and not receipt.get('stop_error') and not active['killed'] and not record.get('io_error')
        record['state'] = 'IDLE' if safe else 'FAULTED'
        record['result'] = receipt.get('result', 'FAILED') if safe else 'FAILED'
        if record['cancellation_requested'] and safe:
            record['result'] = 'CANCELLED'
        if (not receipt and not record['cancellation_requested']) or active['killed']:
            record['result'] = 'FAILED'
        if record.get('budget_reason') and safe:
            record['result'] = 'PARTIAL'
        record['transitions'].append({'state': record['state'], 'time_ns': now()})
        self.faulted |= not safe
        if verification['after'] is not None:
            record['boundary_after'] = verification['after']
            self.boundary_reads += len(verification['after'])
        snapshot = copy.deepcopy(record)
        snapshot['finalized'] = True
        snapshot['process_cpu_budget'] = active['budget'].snapshot()
        previous = copy.deepcopy(self.references)
        minimum = self.schedule.plan['min_samples'] if self.schedule else 32
        def save():
            if snapshot['collector'] == 'ip' and 'boundary_before' in snapshot:
                try:
                    snapshot['survey'] = survey.summarize(snapshot, self.directory/(snapshot['session_id']+'.jsonl'), previous, minimum)
                except (OSError, ValueError, KeyError, TypeError) as error:
                    snapshot['survey_error'] = str(error)
            snapshot['process_cpu_to_report_ns'] = max(0, self.process_cpu()-active['process_cpu_begin'])
            snapshot['cpu_scope'] = 'includes preparation, verification and analysis; final durable write and async kernel costs excluded'
            self.persist(snapshot)
            return snapshot
        # Retain admission ownership through final durable publication.
        active['exited'] = False
        active['publishing'] = True
        record['state'] = 'VERIFY'
        active['deadline'] = now()+CLEANUP_NS
        self.submit_io('final_record', save, self.final_record)

    def final_record(self, saved):
        record = self.active['record']
        late_fault = self.active['killed'] or record.get('io_error')
        late_budget = record.get('budget_reason')
        record.update(saved)
        record['process_cpu_to_publish_ns'] = max(0, self.process_cpu()-self.active['process_cpu_begin'])
        record['publication_accounting'] = 'post-write counter available in live status; pre-write counter persisted'
        record['process_cpu_budget'] = self.active['budget'].snapshot()
        if late_fault:
            record.update(state='FAULTED', result='FAILED', late_publication_fault=True)
            self.faulted = True
        if late_budget:
            record.update(result='PARTIAL' if not late_fault else 'FAILED', budget_reason=late_budget)
        if late_fault or late_budget:
            correction = copy.deepcopy(record)
            record['state'] = 'VERIFY'
            record['finalized'] = False
            self.submit_io('late_publication_receipt', lambda: self.persist(correction),
                           lambda _: self.publish_done(correction))
            return
        self.publish_done(record)

    def publish_done(self, saved):
        record = self.active['record']
        record.update(saved)
        if self.schedule:
            for key in record['targets']:
                value = record.get('survey', {}).get('roots', {}).get(key, {})
                invalid = record['result'] != 'COMPLETE' or self.faulted
                self.schedule.outcome(key, complete=record['result'] == 'COMPLETE',
                                      valid=value.get('valid', False) and not invalid,
                                      candidate=value.get('candidate', False) and not invalid)
                if value:
                    if invalid:
                        value = dict(value, valid=False, candidate=False, status='LATE_BUDGET_OR_FAULT')
                    self.surveys[key] = dict(value, session_id=record['session_id'])
                    reference = self.references.get(key)
                    if value.get('valid') and (reference is None or reference['epoch'] != value['epoch']):
                        self.references[key] = copy.deepcopy(value)
        self.release_active()

    def release_active(self, faulted=False):
        active = self.active
        if faulted:
            active['record'].update(state='FAULTED', result='FAILED')
            self.faulted = True
        for fd in (active['channel'], active['pidfd']):
            try:
                self.selector.unregister(fd)
            except KeyError:
                pass
        active['channel'].close()
        os.close(active['pidfd'])
        self.active = None

    def periodic_tick(self):
        if not self.schedule or self.stopping:
            return
        reason = 'faulted' if self.faulted else 'active_or_draining' if self.active or self.io else None
        proposal = self.schedule.poll(reason)
        if proposal is None:
            return
        request = dict(version=VERSION, op='start', collector='ip', targets=proposal['targets'],
                       window_ms=self.schedule.plan['window_ms'], nonce=secrets.token_hex(16), nonce_epoch=self.nonce_epoch)
        try:
            self.start(request, planned=proposal)
        except (OSError, ValueError, KeyError) as error:
            self.schedule.skips['admission_rejected'] += 1
            self.schedule.recent.append(dict(time_ns=now(), reason=str(error)))
            for key in proposal['targets']:
                self.schedule.roots[key]['attempted_ns'] = now()
                self.schedule.outcome(key)

    def sample_rss(self):
        pids = self.children.pids()
        pids.append(os.getpid())
        pages = 0
        for pid in set(pids):
            try:
                pages += int(Path('/proc/%d/statm' % pid).read_text().split()[1])
            except (FileNotFoundError, ProcessLookupError):
                pass
        return pages*os.sysconf('SC_PAGE_SIZE')

    def run(self):
        while not self.stopping or self.active:
            timeout = min(.1, max(0, (self.active['deadline']-now())/1e9)) if self.active else None
            scheduled = self.schedule.timeout() if self.schedule and not self.stopping else None
            if scheduled is not None:
                timeout = scheduled if timeout is None else min(timeout, scheduled)
            for key, _ in self.selector.select(timeout):
                if key.data == 'server':
                    self.serve_one()
                elif key.data == 'worker' and self.active:
                    self.worker_event()
                elif key.data == 'exit' and self.active:
                    self.finish()
                elif key.data == 'wake':
                    self.wake_r.recv(4096)
            self.pump_io()
            self.periodic_tick()
            if self.active:
                reason = self.active['budget'].check(self.process_cpu(), self.active['record']['state'])
                if reason:
                    self.active['record']['budget_reason'] = reason
                    self.cancel(self.active['record']['session_id'])
                try:
                    rss = self.sample_rss()
                    self.active['memory_peak'] = max(rss, self.active['memory_peak'])
                    if rss > (self.schedule.plan['rss_bytes'] if self.schedule else 64*1024*1024):
                        self.cancel(self.active['record']['session_id'])
                        self.active['record']['budget_reason'] = 'COMBINED_RSS_LIMIT_incomplete_kernel_accounting'
                except (FileNotFoundError, ProcessLookupError):
                    pass
            if self.active and now() >= self.active['deadline']:
                if self.children.poll(self.active['process']) is None:
                    signal.pidfd_send_signal(self.active['pidfd'], signal.SIGKILL)
                self.active['killed'] = True
                self.active['deadline'] = now() + CLEANUP_NS
                self.faulted = True
                self.active['record']['state'] = 'FAULTED'
                if self.schedule:
                    self.schedule.pause()
        for root in self.roots.values():
            os.close(root['fd'])
        self.executor.shutdown(wait=True)
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
    parser.add_argument('--p1-acceptance', help='root-owned receipt matching current source and passed P1 checks')
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
