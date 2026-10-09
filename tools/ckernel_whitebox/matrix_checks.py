"""Fail-closed validation of shared-kernel, deferred-grading runs."""
import json
import re


def validate(text, count):
    matches = re.findall(r'W1_SNAPSHOT ([\w.-]+) (-?\d+) BEGIN\r?\n(.*?)\r?\nW1_SNAPSHOT \1 \2 END', text, re.S)
    snapshots = {(k, int(i)): v.strip() for k, i, v in matches}
    if len(matches) != len(snapshots):
        raise ValueError('duplicate snapshot')
    assert 'W1_MATRIX_END failures=0' in text, 'guest failure'
    assert not any(t in text for t in ('BUG:', 'WARNING:', 'Kernel panic', 'avc:  denied')), 'kernel/security error'
    assert re.search(r'W1_MATRIX_LSM\s+capability,selinux\s', text), 'unexpected LSM'
    done = int(re.findall(r'W1_MATRIX_ALL_DONE (\d+)', text)[0])
    rows = []
    for i in range(count):
        result = json.loads(snapshots['result', i])
        assert result['status'] == 'PASS' and result['slot'] == i
        assert result['replay_exit'] == 0
        official = result['official']
        assert official['status'] == 'PASS'
        if result['workload'] == 'core':
            assert official['metrics']['accuracy'] == 1
        else:
            assert result['workload'] == 'go'
            assert official['official_result']['final_score'] == {'total':2,'result':2}
        identity = result['identity']
        assert identity['pid'] == 1 and ':container_t:' in identity['selinux']
        assert 'Seccomp:\t2' in identity['proc_status'] and 'NoNewPrivs:\t1' in identity['proc_status']
        assert result['grade_start_ns'] >= done
        assert result['identity']['affinity'] == list(range(i*4, i*4+4))
        assert snapshots['memory.max', i] == '4294967296'
        assert snapshots['pids.max', i] == '128'
        assert snapshots['cpuset.cpus.effective', i] == f'{i*4}-{i*4+3}'
        events = dict(line.split() for line in snapshots['memory.events', i].splitlines())
        assert all(events[k] == '0' for k in ('oom', 'oom_kill', 'oom_group_kill'))
        actions = result['action_intervals']
        assert len(actions) == (19 if result['workload'] == 'core' else 6)
        assert all(a['end_ns'] > a['start_ns'] for a in actions)
        assert all(a['end_ns'] <= b['start_ns'] for a, b in zip(actions, actions[1:]))
        assert result['start_ns'] <= actions[0]['start_ns'] < actions[-1]['end_ns'] <= result['end_ns'] <= done
        result['duration_s'] = (actions[-1]['end_ns']-actions[0]['start_ns'])/1e9
        result['memory_peak_bytes'] = int(snapshots['memory.peak', i])
        result['cpu_stat'] = dict((k, int(v)) for k, v in (line.split() for line in snapshots['cpu.stat', i].splitlines()))
        result['io_stat'] = snapshots['io.stat', i]
        rows.append(result)
    start = min(r['action_intervals'][0]['start_ns'] for r in rows)
    end = max(r['action_intervals'][-1]['end_ns'] for r in rows)
    target = rows[0]
    ts, te = target['action_intervals'][0]['start_ns'], target['action_intervals'][-1]['end_ns']
    overlap = [max(0, min(te, r['action_intervals'][-1]['end_ns'])-max(ts, r['action_intervals'][0]['start_ns']))/(te-ts) for r in rows]
    return dict(status='PASS', copies=count, per_copy=rows, batch_s=(end-start)/1e9,
                target_s=target['duration_s'], target_overlap_fractions=overlap,
                start_spread_ms=(max(r['start_ns'] for r in rows)-min(r['start_ns'] for r in rows))/1e6,
                snapshots={k: snapshots[k, -1] for k in ('cpu-before', 'cpu-after', 'memory-before', 'memory-after')})
