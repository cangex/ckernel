"""Replay barrier and deferred official grading, inside each isolated container."""
import json
import os
from pathlib import Path
import resource
import signal
import shutil
import subprocess
import sys
import time
from admission_checks import check_actions


def atomic(path, value):
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(value))
    temp.replace(path)


def wait(path, timeout=600):
    def timed_out(signum, frame):
        raise TimeoutError(str(path))
    previous = signal.signal(signal.SIGALRM, timed_out)
    signal.alarm(timeout)
    try:
        # Blocking FIFO: completed containers do not poll shared filesystem state.
        with path.open() as f:
            return json.load(f)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def compact_actions(actions):
    return [dict(ordinal=i, id=a.get('id'), kind=a['kind'],
                 start_ns=a['start_ns'], end_ns=a['end_ns']) for i,a in enumerate(actions)]


def main():
    control = Path('/matrix-control')
    kind = os.environ['W1_WORKLOAD']
    slot = int(os.environ['W1_SLOT'])
    out = Path('/resultdata')
    out.mkdir(exist_ok=False)
    status = dict(status='FAIL', workload=kind, slot=slot)
    try:
        identity = dict(pid=os.getpid(), selinux=Path('/proc/self/attr/current').read_text().strip(),
                        proc_status=Path('/proc/self/status').read_text(),
                        cgroup=Path('/proc/self/cgroup').read_text(),
                        affinity=sorted(os.sched_getaffinity(0)))
        assert identity['pid'] == 1 and ':container_t:' in identity['selinux']
        assert 'Seccomp:\t2' in identity['proc_status'] and 'NoNewPrivs:\t1' in identity['proc_status']
        assert identity['affinity'] == list(range(slot*4, slot*4+4))
        status['identity'] = identity
        atomic(control/'ready', identity)
        start = wait(control/'start')
        delay = (start - time.monotonic_ns()) / 1e9
        assert delay > 0, 'missed start barrier'
        time.sleep(delay)
        before = time.monotonic_ns()
        with (out/'replay.log').open('w') as log:
            replay = subprocess.run([sys.executable, '/opt/replay/core-replay.py' if kind == 'core'
                                     else '/tac-replay.py'], stdout=log, stderr=subprocess.STDOUT)
        end = time.monotonic_ns()
        status.update(replay_exit=replay.returncode, start_ns=before, end_ns=end,
                      child_usage_business=list(resource.getrusage(resource.RUSAGE_CHILDREN)),
                      wrapper_usage_business=list(resource.getrusage(resource.RUSAGE_SELF)))
        atomic(control/'done', dict(start_ns=before, end_ns=end, exit_code=replay.returncode))
        # No grading or action analysis until every business trajectory has ended.
        wait(control/'grade')
        status['grade_start_ns'] = time.monotonic_ns()
        assert replay.returncode == 0, 'replay failed'
        actions = json.loads(Path('/replay-results/actions.json').read_text())
        issues = check_actions(kind, actions, json.loads(Path('/grade/historical-actions.json').read_text()))
        assert not issues, repr(issues)
        if kind == 'core':
            shutil.copyfile('/replay-results/result.json', '/grade/replay-result.json')
        env = dict(os.environ)
        if kind == 'go':
            env['PATH'] = '/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin'
        grade = subprocess.run([sys.executable, '/grade/core-official-grade.py' if kind == 'core'
                                else '/grade/tac-grade.py'], env=env, capture_output=True, text=True)
        (out/'grade.stdout').write_text(grade.stdout)
        (out/'grade.stderr').write_text(grade.stderr)
        assert grade.returncode == 0, 'official evaluator exit'
        official = json.loads(grade.stdout)
        assert official['status'] == 'PASS'
        if kind == 'core':
            assert official['metrics']['accuracy'] == 1
        else:
            assert official['official_result']['final_score'] == {'total': 2, 'result': 2}
        status.update(status='PASS', official=official, actions=len(actions),
                      action_intervals=compact_actions(actions))
    except Exception as exc:
        status['error'] = repr(exc)
    finally:
        atomic(control/'result', status)
    return 0 if status['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
