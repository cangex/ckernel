# SPDX-License-Identifier: GPL-2.0
import copy
import unittest
from y7_acceptance import matrix
from y7_private_check import order,captures

class FinalMatrix(unittest.TestCase):
    def receipt(self):
        return dict(status='PASS_SCOPED',cohort='private_storage',arrangement='shared',comparisons=[{}]*24,
            states=[dict(**e,status='PASS_SCOPED',errors=[],workloads=[{}]*4,
                observations=[dict(collector=c,quality=dict(status='PASS')) for c in captures(e['mode'])]) for e in order()])
    def test_missing_round_or_source_cannot_complete_y7(self):
        r=self.receipt();matrix(r)
        for change in ('missing_round','missing_source','partial_quality','business_error','missing_pair'):
            x=copy.deepcopy(r)
            if change=='missing_round':x['states'].pop()
            if change=='missing_source':x['states'][2]['observations'].pop()
            if change=='partial_quality':x['states'][2]['observations'][0]['quality']['status']='PARTIAL'
            if change=='business_error':x['states'][0]['errors']=['payload']
            if change=='missing_pair':x['comparisons'].pop()
            with self.assertRaises(ValueError):matrix(x)
