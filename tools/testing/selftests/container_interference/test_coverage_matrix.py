# SPDX-License-Identifier: GPL-2.0
import unittest
from coverage_matrix import validate_index,CONTRACT,VERIFIERS,markdown


class CoverageTests(unittest.TestCase):
    def test_partial_rollback_does_not_replace_prehook_failure(self):
        self.assertEqual(VERIFIERS['allocator_rollback'],('allocator_vm_check','allocator',dict(rollback=True)))
        self.assertEqual(VERIFIERS['allocator_failure'],('allocator_vm_check','allocator',dict(failure=True)))
        self.assertTrue(CONTRACT['allocator']['pending'])

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

    def test_rwsem_and_joint_are_distinct_scoped_evidence(self):
        self.assertIn('rwsem',VERIFIERS)
        self.assertIn('joint',VERIFIERS)
        self.assertIn('集合不保证完整',CONTRACT['rwsem']['participants'])
        self.assertIn('安静专项不算正例',CONTRACT['joint']['participants'])
        self.assertTrue(CONTRACT['rwsem']['pending'])
        self.assertTrue(CONTRACT['joint']['pending'])
