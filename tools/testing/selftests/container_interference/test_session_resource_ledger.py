# SPDX-License-Identifier: GPL-2.0
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'container_interference'))
from p1_admission_check import SOURCE_KEYS
from session_resource_ledger import analyze


class ResourceLedgerTests(unittest.TestCase):
    def log(self, **changes):
        source = {key: 'a'*64 for key in SOURCE_KEYS}
        source['kernel_release'] = 'test'
        record = dict(session_id='3', source_identity=source, collector='owner', result='COMPLETE',
                      controller_cpu_ns=20, reaped_children_cpu_ns=80, observer_process_cpu_ns=100,
                      combined_rss_peak_bytes=1024, receipt=dict(cpu_ns=70, maxrss_kib=1))
        record.update(changes)
        event = dict(session_id=3, kind='kernel_memory_inventory', detail='bpf_maps_fdinfo_bytes=123 total_complete=0')
        return ('CIS_FILE /tmp/records/3.json\n'+json.dumps(record)+'\n'
                'CIS_FILE /tmp/records/3.jsonl\n'+json.dumps(event)+'\n'
                'CIS_FILE /tmp/trailer.txt\n')

    def test_no_double_count_or_rss_total_approval(self):
        report = analyze(self.log())
        self.assertEqual(report['status'], 'BLOCKED')
        row = report['sessions'][0]
        self.assertEqual(row['cpu']['observer_process_cpu_ns'], 100)
        self.assertEqual(row['quality_errors'], [])
        self.assertIsNone(row['memory']['total_upper_bound_bytes'])
        self.assertFalse(row['memory']['total_complete'])

    def test_cpu_mismatch_remains_visible(self):
        row = analyze(self.log(observer_process_cpu_ns=170))['sessions'][0]
        self.assertIn('process CPU identity mismatch', row['quality_errors'])


if __name__ == '__main__':
    unittest.main()
