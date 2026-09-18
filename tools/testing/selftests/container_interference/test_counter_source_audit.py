# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'container_interference'))
from counter_source_audit import parse,delta


class CounterSourceAudit(unittest.TestCase):
    def snapshot(self,n=0,t=1):
        text='version=1 active=0 shift=6 snapshot=non_atomic sequence=10 counter_bytes=384 source_counter_bytes_per_cpu=40\n'
        text+='cpu=0 entries=%d eligible=%d sampled=%d steps=%d capped=0\n'%(n*130,n*128,n*2,n*10)
        return dict(before_ns=t,after_ns=t+1,text=text)

    def test_counts_do_not_become_cost_or_unbiased_population(self):
        r=delta(self.snapshot(),self.snapshot(1,3),6)
        self.assertEqual(r['unsupported_or_recursive_entries'],2)
        self.assertEqual(r['sampled_out_calls'],126)
        self.assertEqual(r['complete_cost'],'UNKNOWN')
        self.assertEqual(r['declared_source_counter_bytes'],40)

    def test_wrap_active_and_bad_boundary_reject(self):
        with self.assertRaises(ValueError): delta(self.snapshot(1),self.snapshot(0,3),6)
        after=self.snapshot(1,3); after['text']=after['text'].replace('active=0','active=1')
        with self.assertRaises(ValueError): delta(self.snapshot(),after,6)
        with self.assertRaises(ValueError): delta(self.snapshot(),self.snapshot(1),6)

    def test_duplicate_cpu_or_incomplete_source_reject(self):
        text=self.snapshot()['text']
        with self.assertRaises(ValueError): parse(text+text.splitlines()[1]+'\n')
        with self.assertRaises(ValueError): parse('version=1 snapshot=non_atomic')


if __name__=='__main__': unittest.main()
