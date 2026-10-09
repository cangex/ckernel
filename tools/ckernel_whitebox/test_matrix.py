import copy
import json
import unittest
from matrix_checks import validate
from matrix_entry import compact_actions


def sample(change=None, omit=None):
    records = {('cpu-before', -1): 'cpu 1 2 3 4', ('cpu-after', -1): 'cpu 2 3 4 5',
               ('memory-before', -1): 'MemFree: 100 kB', ('memory-after', -1): 'MemFree: 90 kB'}
    for i in range(2):
        result = dict(status='PASS', slot=i, workload='core', replay_exit=0,
                      grade_start_ns=10000, start_ns=100, end_ns=1000,
                      identity=dict(affinity=list(range(i*4, i*4+4)), pid=1,
                                    selinux='system_u:system_r:container_t:s0:c1,c2',
                                    proc_status='Seccomp:\t2\nNoNewPrivs:\t1\n'),
                      official=dict(status='PASS',metrics=dict(accuracy=1)),
                      action_intervals=[dict(id=str(a), start_ns=110+a*20, end_ns=120+a*20) for a in range(19)])
        for k, v in {'result': json.dumps(result), 'memory.max': '4294967296', 'pids.max': '128',
                     'cpuset.cpus.effective': f'{i*4}-{i*4+3}', 'memory.events': 'oom 0\noom_kill 0\noom_group_kill 0',
                     'memory.peak': '199000000', 'cpu.stat': 'usage_usec 100', 'io.stat': ''}.items():
            records[k, i] = v
    if change:
        change(records)
    if omit:
        records.pop(omit)
    return 'W1_MATRIX_LSM\ncapability,selinux\nW1_MATRIX_ALL_DONE 9999\nW1_MATRIX_END failures=0\n'+''.join(
        f'W1_SNAPSHOT {k} {i} BEGIN\n{v}\nW1_SNAPSHOT {k} {i} END\n' for (k, i), v in records.items())


class MatrixTests(unittest.TestCase):
    def test_view_without_source_id(self):
        result=compact_actions([dict(kind='file_editor_view', start_ns=1, end_ns=2)])
        self.assertIsNone(result[0]['id'])
        self.assertEqual(result[0]['ordinal'],0)
        self.assertEqual(result[0]['kind'],'file_editor_view')
    def test_valid_and_overlap(self):
        r = validate(sample(), 2)
        self.assertEqual(r['target_overlap_fractions'], [1, 1])

    def test_missing_oom_is_not_zero(self):
        with self.assertRaises(KeyError):
            validate(sample(omit=('memory.events', 1)), 2)

    def test_wrong_cpu(self):
        with self.assertRaises(AssertionError):
            validate(sample(lambda r: r.update({('cpuset.cpus.effective', 1): '0-3'})), 2)

    def test_grading_while_business_rejected(self):
        def change(records):
            r = json.loads(records['result', 0]); r['grade_start_ns'] = 9998
            records['result', 0] = json.dumps(r)
        with self.assertRaises(AssertionError):
            validate(sample(change), 2)

    def test_oom_rejected(self):
        with self.assertRaises(AssertionError):
            validate(sample(lambda r: r.update({('memory.events', 1): 'oom 1\noom_kill 0\noom_group_kill 0'})), 2)

    def test_duplicate_rejected(self):
        with self.assertRaises(ValueError):
            validate(sample()+'W1_SNAPSHOT memory.max 0 BEGIN\n4294967296\nW1_SNAPSHOT memory.max 0 END\n', 2)

    def test_missing_slot_rejected(self):
        with self.assertRaises(KeyError):
            validate(sample(omit=('result', 1)), 2)

    def test_selinux_denial_rejected(self):
        with self.assertRaises(AssertionError):
            validate(sample()+'avc:  denied', 2)

    def test_official_failure_cannot_hide_behind_status(self):
        def change(records):
            r = json.loads(records['result', 1]);r['official']['metrics']['accuracy'] = 0
            records['result', 1] = json.dumps(r)
        with self.assertRaises(AssertionError):
            validate(sample(change), 2)


if __name__ == '__main__':
    unittest.main()
