# SPDX-License-Identifier: GPL-2.0
import copy
import hashlib
import unittest
import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'container_interference'))
from diagnosis_vm_check import saved_timing


class DiagnosisTiming(unittest.TestCase):
    def fixture(self):
        record=dict(boot_id='guest',session_id='7',collector='sched',window=dict(end_ns=100),
                    scheduled=dict(diagnosis=dict(queue_wait_ns=60,sample_age_ns=70)))
        timing=dict(explanation_lag_ns=25,periodic_wait_ns='NOT_INFERRED',
                    specialist_queue_wait_ns=60,sample_age_at_specialist_admit_ns=70)
        saved=dict(record,schema='cis-explanation-v2',raw_sha256=hashlib.sha256(b'raw').hexdigest(),
                   quality=dict(status='PASS'),timing=timing,
                   base=dict(analysis_boot_id='guest',same_clock_as_capture=True,explained_at_ns=125))
        return record,saved

    def test_legacy_base_is_not_relabelled_complete_or_replaced_by_offline_clock(self):
        record,saved=self.fixture()
        checked=saved_timing(record,b'raw',saved)
        self.assertEqual(checked['explanation_boundary'],'legacy_base_summary_only')
        self.assertEqual(checked['explanation_lag_ns'],25)
        self.assertFalse(checked['includes_serialization_or_delivery'])

    def test_full_report_end_is_distinct_from_base_end(self):
        record,saved=self.fixture()
        saved['timing'].update(saved['base'],explained_at_ns=140,explanation_lag_ns=40,
                               explanation_boundary='unified_analysis_complete_before_serialization')
        checked=saved_timing(record,b'raw',saved)
        self.assertEqual(checked['explanation_lag_ns'],40)

    def test_wrong_boot_record_raw_queue_and_negative_lag_are_rejected(self):
        record,original=self.fixture()
        for key,value in (('session_id','other'),('raw_sha256','0'*64),('boot_id','other')):
            saved=copy.deepcopy(original); saved[key]=value
            with self.assertRaises(ValueError): saved_timing(record,b'raw',saved)
        for key,value in (('specialist_queue_wait_ns',0),('explanation_lag_ns',-1),('periodic_wait_ns',25)):
            saved=copy.deepcopy(original); saved['timing'][key]=value
            with self.assertRaises(ValueError): saved_timing(record,b'raw',saved)
        saved=copy.deepcopy(original); saved['base']['analysis_boot_id']='host'
        with self.assertRaises(ValueError): saved_timing(record,b'raw',saved)
