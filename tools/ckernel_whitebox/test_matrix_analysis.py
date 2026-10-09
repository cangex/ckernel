import unittest
from analyze_matrix import summarize, interval


def state(candidate_solo=10, candidate_loaded=18):
    runs=[]
    for r in (1,2,3,4,5):
        for variant in ('baseline','candidate'):
            for copies in (1,12):
                duration=(10 if copies==1 else 20) if variant=='baseline' else (candidate_solo if copies==1 else candidate_loaded)
                runs.append(dict(round=r,variant=variant,copies=copies,status='PASS',workload='core',
                    target_s=duration,batch_s=duration,per_copy=[dict(duration_s=duration,
                    memory_peak_bytes=100,cpu_stat=dict(usage_usec=100)) for _ in range(copies)]))
    return dict(status='PASS',runs=runs)


class AnalysisTests(unittest.TestCase):
    def test_own_solo_denominator(self):
        summary,_=summarize(state(20,20),True)
        self.assertEqual(summary['baseline_interference_pct'],100)
        self.assertEqual(summary['candidate_interference_pct'],0)
        self.assertEqual(summary['absolute_loaded_change_pct'],0)
        self.assertEqual(summary['status'],'COST_TRANSFER_OR_REGRESSION')

    def test_apparent_benefit_still_has_backend_gap(self):
        summary,_=summarize(state(),True)
        self.assertEqual(summary['status'],'PARTIAL_GATES_PASS_BACKEND_COST_UNRESOLVED')

    def test_pilot_is_not_formal_pass(self):
        summary,_=summarize(state())
        self.assertEqual(summary['status'],'EXPLORATORY_ONLY')

    def test_failed_state_not_dropped(self):
        s=state();s['runs'][0]['status']='FAIL'
        with self.assertRaises(AssertionError):summarize(s)

    def test_duplicate_not_pseudoreplication(self):
        s=state();s['runs'].append(s['runs'][0])
        with self.assertRaises(AssertionError):summarize(s)

    def test_constant_ratio(self):
        v=interval([.9]*5)
        self.assertAlmostEqual(v['low_percent'],-10)
        self.assertAlmostEqual(v['high_percent'],-10)


if __name__ == '__main__':unittest.main()
