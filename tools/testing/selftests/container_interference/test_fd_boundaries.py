# SPDX-License-Identifier: GPL-2.0
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'container_interference'))
from fd_vm_check import verify_boundaries


class FDBoundaries(unittest.TestCase):
    def test_preparation_before_window_does_not_admit_early_operations(self):
        names=['a.log','b.log'];window=dict(start_ns=100,end_ns=200)
        bounds=dict(logs=names,groups=[dict(generation=0,start_ns=90,end_ns=180)])
        logs=['CIS_FD_TRUTH '+json.dumps(dict(begin_ns=110,released_ns=170))]*2
        self.assertEqual(verify_boundaries(bounds,names,logs,window,80),[])
        for begin,end in ((99,170),(110,181),(110,201)):
            bad=['CIS_FD_TRUTH '+json.dumps(dict(begin_ns=begin,released_ns=end))]*2
            self.assertIn('operation_outside_window_or_lifetime',verify_boundaries(bounds,names,bad,window,80))

    def test_missing_or_reordered_generations_are_rejected(self):
        bounds=dict(logs=['a','b'],groups=[dict(generation=1,start_ns=10,end_ns=20)])
        result=verify_boundaries(bounds,['a','b'],['',''],dict(start_ns=1,end_ns=30),0)
        self.assertIn('group_order',result)
        self.assertIn('missing_operation_boundaries',result)


if __name__=='__main__': unittest.main()
