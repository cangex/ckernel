# SPDX-License-Identifier: GPL-2.0
import importlib.util
from pathlib import Path
import sys
import unittest
directory=Path(__file__).resolve().parents[3]/'container_interference'
sys.path.insert(0,str(directory))
import session_check

class EvidenceChecks(unittest.TestCase):
    def test_missing_evidence_is_not_pass(self):
        result=session_check.analyze('CIS_PROFILE_VM_FUNCTIONAL_PASS=1\nCIS_PROFILE_VM_EXIT=0')
        self.assertFalse(result['phase_complete'])
        self.assertEqual(result['repeat']['ip']['status'],'BLOCKED')
        self.assertTrue(all(row['status']=='BLOCKED' for row in result['cost']))

    def test_small_n_has_no_fabricated_ci(self):
        self.assertEqual(session_check.interval([0,0,0])['status'],'BLOCKED')

    def test_pair_interval(self):
        result=session_check.interval([0,1,2,3,4])
        self.assertEqual(result['mean_pct'],2)
        self.assertGreater(result['upper95_pct'],2)

    def test_file_boundaries(self):
        result=session_check.extract('CIS_FILE /a\nx\nCIS_FILE /b\ny\n')
        self.assertEqual(result,{'/a':'x','/b':'y'})

if __name__=='__main__':unittest.main()
