# SPDX-License-Identifier: GPL-2.0
import unittest
from coverage_matrix import validate_index,CONTRACT,markdown


class CoverageTests(unittest.TestCase):
    def test_evidence_is_nonempty_bounded_and_cannot_choose_arbitrary_code(self):
        valid=dict(schema='cis-coverage-input-v1',cohorts=[dict(name='block-native',verifier='block',serial='evidence.log',sha256='0'*64)])
        self.assertEqual(len(validate_index(valid)),1)
        for changed in (dict(valid,cohorts=[]),dict(valid,cohorts=valid['cohorts']*2),
                        dict(valid,cohorts=[dict(valid['cohorts'][0],verifier='os')]),
                        dict(valid,cohorts=[dict(valid['cohorts'][0],name='../bad')])):
            with self.assertRaises(ValueError): validate_index(changed)

    def test_no_full_owner_claim_for_atomic_counter_or_generic_rwsem(self):
        self.assertIn('不是锁持有者',CONTRACT['counter']['participants'])
        self.assertIn('不得推断持有者',CONTRACT['sync']['participants'])
        rows=[dict(v,cohort_status='UNVERIFIED') for v in CONTRACT.values()]
        report=markdown(dict(rows=rows))
        self.assertIn('尚未完成',report)
        self.assertIn('原始日志哈希',report)
