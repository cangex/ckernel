import unittest
from analyze_matrix import paired_ratio, t_quantile, peers

class AnalysisTest(unittest.TestCase):
    def test_student_reference(self):
        self.assertAlmostEqual(t_quantile(.975, 7), 2.364624251, places=7)

    def test_identical(self):
        r = paired_ratio([1., 2., 3.], [1., 2., 3.], 2.)
        self.assertEqual(r, dict(ratio=1., low=1., high=1.))

    def test_multiplier(self):
        r = paired_ratio([.8, 1.6, 2.4], [1., 2., 3.], 2.)
        self.assertAlmostEqual(r['ratio'], .8)

    def test_invalid_pairing(self):
        with self.assertRaises(ValueError):
            paired_ratio([1., 2.], [1.], 2.)

    def test_target_not_in_peer_average(self):
        self.assertEqual(peers({'business': {'instances': [dict(slot=0, elapsed_s=99),
                                                         dict(slot=1, elapsed_s=1),
                                                         dict(slot=2, elapsed_s=3)]}}), 2)

if __name__ == '__main__':
    unittest.main()
