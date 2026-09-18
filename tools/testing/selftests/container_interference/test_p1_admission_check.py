# SPDX-License-Identifier: GPL-2.0
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'container_interference'))
from p1_admission_check import SOURCE_KEYS, REQUIRED_EVIDENCE, evaluate
from periodic_plan import P1_CHECKS


class EvidenceAdmission(unittest.TestCase):
    def test_every_gate_has_an_explicit_evidence_contract(self):
        self.assertEqual(set(REQUIRED_EVIDENCE),set(P1_CHECKS))
        self.assertTrue(all(len(value)>40 for value in REQUIRED_EVIDENCE.values()))

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

    def test_bounded_failure_is_not_hidden_by_missing_coverage(self):
        for nonce,check in [('cancelActive','lifecycle_runtime'),
                            ('stageobjectload','resource_failure_runtime'),
                            ('fdLimit4','resource_failure_runtime')]:
            failed=self.raw().replace(b'"nonce": "test"',json.dumps('nonce').encode()+b': '+json.dumps(nonce).encode())
            failed=failed.replace(b'"objects_absent": true',b'"objects_absent": false')
            result=evaluate(self.source(),[('failed',failed),('incomplete',self.raw())])
            self.assertEqual(result['checks'][check],'FAIL')
            self.assertFalse(result['phase_complete'])
