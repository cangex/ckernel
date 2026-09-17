# SPDX-License-Identifier: GPL-2.0
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'container_interference'))
from p1_admission_check import SOURCE_KEYS, evaluate


class EvidenceAdmission(unittest.TestCase):
    def source(self):
        return {key: 'test-kernel' if key == 'kernel_release' else 'a' * 64 for key in SOURCE_KEYS}

    def raw(self, source=None):
        record = dict(session_id=1, nonce='test', source_identity=source or self.source(),
                      result='COMPLETE', objects_absent=True)
        return ('CIS_FILE /tmp/session-evidence/records/1.json\n' + json.dumps(record) +
                '\nCIS_PROFILE_VM_EXIT=0\n').encode()

    def test_summary_pass_cannot_admit(self):
        with self.assertRaises(ValueError):
            evaluate(self.source(), [('fake', b'{"phase_complete":true,"checks":{"all":"PASS"}}')])

    def test_no_evidence_cannot_admit(self):
        with self.assertRaises(ValueError):
            evaluate(self.source(), [])

    def test_valid_source_missing_runtime_checks_stays_blocked(self):
        result = evaluate(self.source(), [('raw', self.raw())])
        self.assertFalse(result['phase_complete'])
        self.assertEqual(result['checks']['total_memory_cost'], 'BLOCKED')
        self.assertEqual(result['checks']['idle_p99'], 'BLOCKED')

    def test_source_mismatch_and_duplicate_evidence(self):
        other = self.source()
        other['bpf_sha256'] = 'b' * 64
        with self.assertRaises(ValueError):
            evaluate(self.source(), [('old', self.raw(other))])
        with self.assertRaises(ValueError):
            evaluate(self.source(), [('first', self.raw()), ('again', self.raw())])

    def test_missing_source_hash(self):
        source = self.source()
        del source['kernel_notes_sha256']
        with self.assertRaises(ValueError):
            evaluate(source, [('raw', self.raw())])
