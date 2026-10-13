import unittest
from cost_report import cpu_busy_ticks, device_counts, delta, journal_transactions


class CostTests(unittest.TestCase):
    def test_guest_cpu_not_double_counted(self):
        self.assertEqual(cpu_busy_ticks('cpu 10 2 3 100 50 4 5 6 10 2\n'), 24)

    def test_cpu_subset(self):
        text = 'cpu 20 0 10 0 0 2 4\ncpu112 3 0 2 0 0 1 2\n'
        self.assertEqual(cpu_busy_ticks(text, [112]), 8)

    def test_only_named_physical_device(self):
        text = '8 0 sda 1 2 3 4 5 6 7 8 9 10 11 0 0 0 0 12 13\n253 0 dm-0 9 0 99 0 9 0 99 0 0 0 0\n'
        r = device_counts(text, 'sda')
        self.assertEqual(r['read_bytes'], 1536)
        self.assertEqual(r['write_bytes'], 3584)
        self.assertEqual(r['flushes'], 12)

    def test_reset_is_not_zero(self):
        with self.assertRaises(ValueError):
            delta({'x': 5}, {'x': 1})

    def test_journal_identity_and_counts(self):
        self.assertEqual(journal_transactions({'a': '2 transactions x'}, {'a': '4 transactions x'}), 2)
        with self.assertRaises(ValueError):
            journal_transactions({'a': '2 transactions x'}, {'b': '4 transactions x'})


if __name__ == '__main__':
    unittest.main()
