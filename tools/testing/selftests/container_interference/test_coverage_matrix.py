# SPDX-License-Identifier: GPL-2.0
import unittest
import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
from coverage_matrix import validate_index,CONTRACT,VERIFIERS,markdown,replay


class CoverageTests(unittest.TestCase):
    def test_presubmit_cancellation_cannot_certify_inflight_abort(self):
        checked=dict(status='PASS',fixture='inflight',states=[dict(label='%s-block-r%d'%(case,i),
            result=dict(driver_requests=2,canceled_before_submit=False,driver_aborted_inflight=case=='abort',
                        deferred_normal_completion=case=='drain')) for case in ('abort','drain') for i in range(1,4)])
        module=SimpleNamespace(__file__=__file__,verify=lambda *a,**k:checked)
        with tempfile.TemporaryDirectory() as tmp,patch('coverage_matrix.importlib.import_module',return_value=module):
            base=Path(tmp); (base/'serial.log').write_bytes(b'fixture')
            row=dict(name='inflight',serial='serial.log',sha256=hashlib.sha256(b'fixture').hexdigest())
            def check(kind,name):
                return replay(dict(schema='cis-coverage-input-v1',cohorts=[dict(row,verifier=kind)]),base,base/name)['evidence'][0]['status']
            self.assertEqual(check('block_inflight','inflight'),'PASS_SCOPED')
            self.assertEqual(check('block_lifecycle','not-presubmit'),'FAIL')
            checked['fixture']='lifecycle'
            self.assertEqual(check('block_inflight','not-inflight'),'FAIL')

    def test_cpu_guard_is_not_socket_owner_validation(self):
        checked=dict(status='PASS',states=[dict(label='storm-net%d'%i,
            result=dict(reason='COMBINED_PROCESS_CPU_CAPTURING',post_detach_operations=[100,100])) for i in range(3)])
        module=SimpleNamespace(__file__=__file__,verify=lambda *a,**k:checked)
        with tempfile.TemporaryDirectory() as tmp,patch('coverage_matrix.importlib.import_module',return_value=module):
            base=Path(tmp); (base/'serial.log').write_bytes(b'fixture')
            row=dict(name='storm',serial='serial.log',sha256=hashlib.sha256(b'fixture').hexdigest())
            def check(kind,name):
                return replay(dict(schema='cis-coverage-input-v1',cohorts=[dict(row,verifier=kind)]),base,base/name)['evidence'][0]['status']
            self.assertEqual(check('net_guard','guard'),'PASS_SCOPED')
            self.assertEqual(check('net','not-owner'),'FAIL')
            checked['states'][0]['result']['reason']='CANCELLED'
            self.assertEqual(check('net_guard','not-budget'),'FAIL')
            checked['states'][0]['result'].update(reason='COMBINED_PROCESS_CPU_CAPTURING',post_detach_operations=[100,0])
            self.assertEqual(check('net_guard','stopped-business'),'FAIL')

    def test_failed_sends_are_not_socket_ownership_or_success_only_evidence(self):
        checked=dict(status='PASS',states=[dict(label='%s-net%d'%(case,i),
            result=dict(participants=[dict(eligible=8,captured=8)]*2))
            for case in ('txfailure','txunmarked') for i in range(3)])
        module=SimpleNamespace(__file__=__file__,verify=lambda *a,**k:checked)
        with tempfile.TemporaryDirectory() as tmp,patch('coverage_matrix.importlib.import_module',return_value=module):
            base=Path(tmp);(base/'serial.log').write_bytes(b'fixture')
            row=dict(name='txfailure',serial='serial.log',sha256=hashlib.sha256(b'fixture').hexdigest())
            for kind,expected in (('net_tx_failure','PASS_SCOPED'),('net','FAIL'),('net_tx','FAIL')):
                index=dict(schema='cis-coverage-input-v1',cohorts=[dict(row,verifier=kind)])
                self.assertEqual(replay(index,base,base/kind)['evidence'][0]['status'],expected)

    def test_capacity_protection_does_not_certify_logical_ownership(self):
        checked=dict(status='PASS',states=[dict(label='capacity-net%d'%i,
            result=dict(native_cookies=80,quality=dict(status='FAIL'))) for i in range(3)])
        module=SimpleNamespace(__file__=__file__,verify=lambda *a,**k:checked)
        with tempfile.TemporaryDirectory() as tmp,patch('coverage_matrix.importlib.import_module',return_value=module):
            base=Path(tmp);(base/'serial.log').write_bytes(b'fixture')
            row=dict(name='capacity',serial='serial.log',sha256=hashlib.sha256(b'fixture').hexdigest())
            def check(kind,name):
                index=dict(schema='cis-coverage-input-v1',cohorts=[dict(row,verifier=kind)])
                return replay(index,base,base/name)['evidence'][0]['status']
            self.assertEqual(check('net_capacity','guard'),'PASS_SCOPED')
            self.assertEqual(check('net','not-owner'),'FAIL')
            checked['states'][0]['result']['quality']['status']='PASS'
            self.assertEqual(check('net_capacity','not-rejected'),'FAIL')

    def test_offline_evidence_capacity_is_not_live_admission_capacity(self):
        rows=[dict(name='case-%d'%i,verifier='block_merge',serial='evidence.log',sha256='0'*64) for i in range(64)]
        self.assertEqual(len(validate_index(dict(schema='cis-coverage-input-v1',cohorts=rows))),64)
        with self.assertRaises(ValueError):
            validate_index(dict(schema='cis-coverage-input-v1',cohorts=rows+[dict(rows[0],name='extra')]))
        self.assertIn('不推断设备阻塞方',CONTRACT['block_merge']['participants'])

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

    def test_fd_call_denominator_cannot_be_upgraded_to_wait_recall(self):
        self.assertIn('不等于真实阻塞关系召回','；'.join(CONTRACT['fd']['pending']))
        self.assertIn('64事件前缀','；'.join(CONTRACT['fd']['pending']))
