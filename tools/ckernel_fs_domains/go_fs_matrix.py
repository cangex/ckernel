#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Matched loop-ext4 Go experiment; no host reconfiguration or kernel changes."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import threading
import time

import go_fs_admission as admission
from fs_domain_lifecycle import Manager, run, save
from fs_domain_plan import COUNTS, GIB, layout, placement, required_free
from fs_events import ActionWatch, final_go_action

ROOT = Path('/root/ckernel-fs-domains-20261013')
LABEL = 'fs-domain-matrix-20261013'
TOTAL_INODES = 787968  # 5472 per 128MiB block group, exact for all four layouts.

def geometry(volumes):
    rows = []
    for v in volumes:
        fields = dict(line.split(':', 1) for line in v['superblock'].splitlines() if ':' in line)
        numeric = lambda name: int(fields[name].strip())
        row = dict(bytes=numeric('Block count') * numeric('Block size'),
                   inodes=numeric('Inode count'), journal_blocks=numeric('Total journal blocks'),
                   features=fields['Filesystem features'].split(), capacity=v['capacity'], uuid=v['uuid'])
        assert row['bytes'] == v['spec']['bytes'] and row['inodes'] == v['spec']['inodes']
        assert row['journal_blocks'] * 4096 == v['spec']['journal_mib'] * 1024**2
        rows.append(row)
    assert sum(r['bytes'] for r in rows) == 18 * GIB
    assert sum(r['inodes'] for r in rows) == TOTAL_INODES
    assert sum(r['journal_blocks'] * 4096 for r in rows) == 384 * 1024**2
    assert all(r['features'] == rows[0]['features'] for r in rows)
    return rows

def cpu_stat(text):
    return {k: int(v) for k, v in (line.split() for line in text.splitlines())}

def phase_snapshot():
    begin = time.monotonic_ns()
    value = dict(begin_ns=begin, host_cpu=Path('/proc/stat').read_text(),
                 diskstats=Path('/proc/diskstats').read_text(), meminfo=Path('/proc/meminfo').read_text())
    value['end_ns'] = time.monotonic_ns()
    return value

def kernel_tasks():
    values = {}
    for p in Path('/proc').iterdir():
        if not p.name.isdigit():
            continue
        try:
            s = (p / 'stat').read_text()
            left, right = s.index('('), s.rindex(')')
            name, f = s[left + 1:right], s[right + 2:].split()
            if name.startswith(('jbd2/', 'kworker/', 'ksoftirqd/', 'kswapd', 'kcompactd')):
                values[p.name + ':' + f[19]] = dict(name=name, cpu_ticks=int(f[11]) + int(f[12]))
        except (FileNotFoundError, ProcessLookupError):
            pass
    return values

def snapshot(cgroups, volumes):
    begin = time.monotonic_ns()
    result = dict(begin_ns=begin, host_cpu=Path('/proc/stat').read_text(),
                  diskstats=Path('/proc/diskstats').read_text(), meminfo=Path('/proc/meminfo').read_text(),
                  cgroups={str(s): {f: (cg / f).read_text() for f in
                                   ('cpu.stat', 'memory.current', 'memory.peak', 'memory.events', 'io.stat')
                                   if (cg / f).exists()} for s, cg in cgroups.items()},
                  journals={})
    journals = {Path(v['loop']).name for v in volumes}
    for p in Path('/proc/fs/jbd2').glob('*/info'):
        if p.parent.name.rsplit('-', 1)[0] in journals:
            result['journals'][str(p)] = p.read_text()
    result['end_ns'] = time.monotonic_ns()
    return result

class Window:
    def __init__(self, cgroups, volumes, actions):
        self.cgroups, self.volumes = cgroups, volumes
        self.actions = actions
        self.stop = threading.Event()
        self.ready = threading.Event()
        self.samples = []
        self.error = None

    def start(self, at):
        self.at = at
        begin = time.thread_time_ns()
        self.watch = ActionWatch(self.actions)
        self.watch_setup_cpu_ns = time.thread_time_ns() - begin
        self.thread = threading.Thread(target=self.worker, name='ckfs-window')
        self.thread.start()

    def worker(self):
        cpu = time.thread_time_ns()
        try:
            delay = max(0, (self.at - time.monotonic_ns()) / 1e9)
            if self.stop.wait(delay):
                raise RuntimeError('cancelled before business boundary')
            self.before = snapshot(self.cgroups, self.volumes)
            self.ready.set()
            def endpoint(snap):
                return dict(ns=time.monotonic_ns(),
                    memory_bytes=sum(int(v['memory.current']) for v in snap['cgroups'].values()),
                    used_bytes=sum((s.f_blocks - s.f_bfree) * s.f_frsize
                                   for s in (os.statvfs(v['mount']) for v in self.volumes)))
            self.samples.append(endpoint(self.before))
            complete, changed = {}, set(self.actions)
            while True:
                for slot in changed:
                    path = self.actions[slot]
                    if slot in complete:
                        continue
                    try:
                        record = final_go_action(path)
                        if record is not None:
                            complete[slot] = record['end_ns']
                    except (FileNotFoundError, json.JSONDecodeError):
                        pass
                if len(complete) == len(self.actions):
                    self.completed_actions = complete
                    # The frozen logger closes actions.json immediately before
                    # publishing its end timestamp. Keep a fixed 5ms guard and
                    # validate the observed offset against that timestamp later.
                    time.sleep(.005)
                    break
                if self.stop.is_set():
                    raise RuntimeError('orchestrator stopped before all final actions observed')
                changed = self.watch.poll(.2)
            self.after = snapshot(self.cgroups, self.volumes)
            self.samples.append(endpoint(self.after))
        except BaseException as e:
            self.error = repr(e)
        finally:
            self.watch.close()
            self.cpu_ns = time.thread_time_ns() - cpu
            self.ready.set()

    def finish(self):
        if not hasattr(self, 'thread'):
            return
        self.stop.set()
        self.thread.join(10)
        if self.thread.is_alive() or self.error:
            raise RuntimeError(('window sampler', self.error))

    def result(self):
        b, a = self.before, self.after
        business = sum(cpu_stat(a['cgroups'][s]['cpu.stat'])['usage_usec'] -
                       cpu_stat(b['cgroups'][s]['cpu.stat'])['usage_usec'] for s in b['cgroups']) / 1e6
        return dict(before=b, after=a, sampled_peak=self.samples,
            business_cpu_s=business, stable_kernel_task_cpu_s=None,
            completion_source='existing in-container actions.json; unchanged replay script',
            completed_actions=self.completed_actions,
            sampler_cpu_ns=self.cpu_ns, new_kernel_tasks=[], lost_kernel_tasks=[], kernel_task_capture=False,
            watch_setup_cpu_ns=self.watch_setup_cpu_ns,
            limitations=['Host-wide counters include unrelated services.',
                        'OFF does not scan kernel tasks; host CPU totals do not identify background ownership.',
                        'Memory/current-space samples are endpoints only. Per-copy kernel memory.peak is retained separately; their sum is not an exact simultaneous peak.',
                        'Snapshots span their recorded intervals, not exactly replay start/end.'])

class BarrierClock:
    def __init__(self, callback):
        self.callback = callback
        self.used = False

    def __getattr__(self, name):
        return getattr(time, name)

    def monotonic_ns(self):
        if self.used:
            raise RuntimeError('unexpected frozen runner clock call')
        self.used = True
        now = time.monotonic_ns()
        self.callback(now + 2_000_000_000)
        return now

def execute(m, root, spec):
    name, domains, n, rotation = (spec[k] for k in ('name', 'domains', 'n', 'rotation'))
    slots = list(range(n))
    if run(['docker', 'ps', '-q', '--filter', 'label=wb.native']).strip():
        raise RuntimeError('another owned experiment active')
    if shutil.disk_usage('/').free < required_free(18 * GIB, n):
        raise RuntimeError('capacity below frozen budget')
    parent = root / name
    parent.mkdir()
    manager = Manager(parent / 'volumes', True)
    old_cmd, old_stats, old_time = m.cmd, m.stats, m.time
    created, paths, cgroups, container_pids = [], {}, {}, {}
    window = None
    begin = time.monotonic_ns()
    result = dict(status='FAIL', spec=spec, phase_counters={'before_setup': phase_snapshot()})
    try:
        manager.create_volumes(layout(domains, total_inodes=TOTAL_INODES))
        for s in slots:
            paths[s] = manager.private_directory(s, placement(s, domains, rotation))
        result['geometry'] = geometry(manager.state['volumes'])
        result['setup_ns'] = time.monotonic_ns() - begin
        result['bindings'] = manager.state['bindings']
        for v in manager.state['volumes']:
            run(['sync', '-f', v['mount']])
        # This flush targets only the filesystem hosting these task-owned images.
        run(['sync', '-f', str(parent)])
        time.sleep(1)
        result['phase_counters']['after_initialization_drain'] = phase_snapshot()
        before_calls = 0
        finished = False

        def start_window(at):
            nonlocal window
            for s in slots:
                p = root / 'states' / name / str(s) / 'identity.json'
                identity = json.loads(p.read_text())
                cgroups[s] = Path('/sys/fs/cgroup' + identity['cgroup'])
                identity.update(storage='matched-loop-ext4-bind', fs_domain=placement(s, domains, rotation),
                                output_path=str(paths[s]))
                save(p, identity)
            if time.monotonic_ns() > at - 100_000_000:
                raise RuntimeError('identity publication missed start barrier')
            action_paths = {s: Path(f'/proc/{container_pids[s]}/root/replay-results/actions.json') for s in slots}
            window = Window(cgroups, manager.state['volumes'], action_paths)
            window.start(at)

        def command(args, timeout=60, check=True):
            nonlocal finished
            args = list(args)
            if args[:2] == ['docker', 'create']:
                slot = int(args[args.index('--name') + 1].rsplit('-', 1)[1])
                args[2:2] = ['--label', 'wb.native=' + LABEL, '-v', str(paths[slot]) + ':/usr/local/go:Z']
            if args[:2] == ['docker', 'inspect'] and '--size' in args and not finished:
                if window is None:
                    raise RuntimeError('missing window')
                window.finish()
                finished = True
                save(parent / 'window.json', window.result())
            if args[:2] in (['docker', 'stop'], ['docker', 'rm']):
                obj = json.loads(old_cmd(['docker', 'inspect', args[-1]]).stdout)[0]
                if obj['Config']['Labels'].get('wb.native') != LABEL:
                    raise RuntimeError('foreign cleanup refused')
            q = old_cmd(args, timeout=timeout, check=check)
            if args[:2] == ['docker', 'inspect'] and '--size' not in args and q.returncode == 0:
                for obj in json.loads(q.stdout):
                    if obj.get('Config', {}).get('Labels', {}).get('wb.native') == LABEL and obj['State']['Running']:
                        slot = int(obj['Name'].rsplit('-', 1)[1])
                        container_pids[slot] = obj['State']['Pid']
            if args[:2] == ['docker', 'create'] and q.returncode == 0:
                created.append(q.stdout.strip())
            return q

        def stats(cgroup):
            nonlocal before_calls
            before_calls += 1
            if before_calls <= n:
                return old_stats(cgroup)
            slot = next(s for s, p in cgroups.items() if p == cgroup)
            return window.after['cgroups'][str(slot)]

        m.cmd, m.stats, m.time = command, stats, BarrierClock(start_window)
        m.ROOT, m.HOME_FROM = root, 48
        m.shutil, m.capacity, m.freeze = admission.Guard(), admission.capacity, lambda: admission.freeze(m)
        row = m.state(name, slots, 'off')
        if row['status'] != 'PASS' or not finished:
            raise RuntimeError('business admission failed')
        costs = window.result()
        result['phase_counters']['after_scoring_and_container_exit'] = phase_snapshot()
        result.update(status='PASS', business=row, business_cpu_s=costs['business_cpu_s'],
            stable_kernel_task_cpu_s=costs['stable_kernel_task_cpu_s'],
            sampler_cpu_ns=costs['sampler_cpu_ns'],
            sampled_peak_memory_bytes=max(v['memory_bytes'] for v in window.samples),
            memory_observation='endpoint_current_and_per_copy_kernel_peak',
            summed_copy_peak_memory_bytes=sum(int(v['memory.peak']) for v in window.after['cgroups'].values()),
            sampled_peak_used_bytes=max(v['used_bytes'] for v in window.samples),
            batch_s=(max(v['end_ns'] for v in row['instances']) - min(v['start_ns'] for v in row['instances'])) / 1e9,
            peer_mean_s=sum(v['elapsed_s'] for v in row['instances'] if v['slot'] != 0) / (n - 1) if n > 1 else row['target_s'],
            output_bytes={str(s): int(run(['du', '-sx', '-B1', str(p)]).split()[0]) for s, p in paths.items()})
    except BaseException as e:
        result['error'] = repr(e)
        raise
    finally:
        m.cmd, m.stats, m.time = old_cmd, old_stats, old_time
        if window is not None:
            try:
                window.finish()
            except BaseException as e:
                result['sampler_cleanup_error'] = repr(e)
        for cid in created:
            q = old_cmd(['docker', 'inspect', cid], check=False)
            if q.returncode:
                continue
            obj = json.loads(q.stdout)[0]
            if obj['Config']['Labels'].get('wb.native') != LABEL:
                raise RuntimeError('foreign retained container')
            save(parent / (cid[:12] + '-final.json'), obj)
            if obj['State']['Running']:
                old_cmd(['docker', 'stop', '--time', '3', cid])
            old_cmd(['docker', 'rm', cid])
        drain = time.monotonic_ns()
        try:
            manager.teardown(True)
        except BaseException as e:
            result.update(status='FAIL', teardown_error=repr(e))
            raise
        finally:
            manager.close()
            result.update(teardown_ns=time.monotonic_ns() - drain, total_ns=time.monotonic_ns() - begin)
            result['phase_counters']['after_teardown'] = phase_snapshot()
            result['teardown_command_ns'] = {}
            for item in manager.state['commands']:
                if item['begin_ns'] >= drain:
                    command = item['argv'][0]
                    result['teardown_command_ns'][command] = result['teardown_command_ns'].get(command, 0) + item['end_ns'] - item['begin_ns']
            save(parent / 'result.json', result)
    admission.freeze(m)
    return result

def plan(phase):
    orders = [(1, 2, 4, 24), (24, 4, 2, 1), (2, 24, 1, 4)] if phase == 'pilot' else [
        (1, 2, 24, 4), (2, 4, 1, 24), (4, 24, 2, 1), (24, 1, 4, 2),
        (4, 24, 2, 1), (24, 1, 4, 2), (1, 2, 24, 4), (2, 4, 1, 24)]
    rows = []
    for block, order in enumerate(orders):
        for d in order:
            for n in ((1, 24) if block % 2 == 0 else (24, 1)):
                rows.append(dict(name=f'{phase}-b{block}-d{d}-n{n}', domains=d, n=n,
                                 block=block, rotation=(block * 5) % 24))
    return rows

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('phase', choices=('pilot', 'formal'))
    ap.add_argument('--tag', required=True)
    args = ap.parse_args()
    if not re.fullmatch(r'[a-z0-9-]+', args.tag):
        raise ValueError('tag')
    os.umask(0o077)
    os.sched_setaffinity(0, {112, 113, 114, 115})
    lock = (ROOT / 'matrix.lock').open('a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    m, inputs = admission.load()
    root = ROOT / args.tag
    root.mkdir()
    work = plan(args.phase)
    if args.phase == 'formal':
        frozen = ROOT / 'formal-freeze-r1.json'
        protocol = json.loads(frozen.read_text())
        if protocol.get('admitted') is not True or protocol.get('states') != work:
            raise RuntimeError('formal protocol not frozen after pilot')
    save(root / 'plan.json', dict(phase=args.phase, states=work, boot=admission.BOOT,
        kernel=admission.KERNEL, image=m.IMAGE, inputs=inputs,
        source_hashes={p.name: admission.sha(p) for p in Path(__file__).parent.glob('*.py')},
        gross_budget=dict(bytes=18 * GIB, inodes=TOTAL_INODES, journal_bytes=384 * 1024**2),
        storage='all arms use fresh fully allocated loop-file ext4 on the same root filesystem',
        note='Observation kernel, not unmodified OLK. No hotpath changes. OFF has bounded identical summary sampling.',
        cache='fresh container and ext4 per state, explicit initialization drain; no global cache flush',
        grading='all copies after ALL measured business finished'))
    results = []
    for spec in work:
        row = execute(m, root, spec)
        results.append(row)
        save(root / 'progress.json', results)
        print(json.dumps(dict(spec=spec, status=row['status'], target_s=row['business']['target_s'],
                              batch_s=row['batch_s'], teardown_s=row['teardown_ns'] / 1e9)), flush=True)
    save(root / 'summary.json', dict(status='PASS', phase=args.phase, states=len(results),
        copies=sum(len(v['business']['instances']) for v in results), results=results,
        conclusion='Correctness and execution completion only; statistical and mechanism analysis separate.'))

if __name__ == '__main__':
    main()
