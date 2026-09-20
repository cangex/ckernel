# SPDX-License-Identifier: GPL-2.0
import copy
import unittest
from y7_acceptance import matrix,first_analysis_timing
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

    def test_first_analysis_uses_capture_clock_not_replay_clock(self):
        state=dict(explanation_ready_ns=50,sessions=[dict(collector='cpu',session_id='1',scheduled_ns=5)])
        record=dict(collector='cpu',session_id='1',boot_id='guest',requested_ns=10,
            window=dict(start_ns=20,end_ns=30))
        checked=dict(observations=[dict(collector='cpu',quality=dict(status='PASS'),
            report_timing=dict(explained_at_ns=40,analysis_boot_id='guest',same_clock_as_capture=True,explanation_lag_ns=10))])
        result=first_analysis_timing(state,checked,[record])[0]
        self.assertEqual(result['request_to_window_ns'],10)
        self.assertEqual(result['window_end_to_first_explanation_ns'],10)
        for key,value in [('analysis_boot_id','host'),('same_clock_as_capture',False),
                          ('explained_at_ns',60),('explanation_lag_ns',11)]:
            bad=copy.deepcopy(checked);bad['observations'][0]['report_timing'][key]=value
            with self.assertRaises(ValueError):first_analysis_timing(state,bad,[record])
