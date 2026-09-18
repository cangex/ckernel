# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'container_interference'))
from vm_time_alignment import align, sched_delta


class ClockBounds(unittest.TestCase):
    def samples(self):
        return [dict(sequence=i,host_send_ns=1000+i*1000,guest_receive_ns=100+i*1000,
                     guest_send_ns=110+i*1000,host_receive_ns=1200+i*1000) for i in range(3)]

    def test_asymmetry_retained(self):
        result=align(self.samples(),1100,0)
        self.assertEqual(result['offset_interval_ns'],[900,1090])
        self.assertFalse(result['causal_attribution'])
        self.assertEqual(result['uncertainty_width_ns'],190)

    def test_invalid_and_inconsistent(self):
        rows=self.samples();rows[1]['guest_receive_ns']=0
        with self.assertRaises(ValueError):align(rows,100,0)
        rows=self.samples();rows[-1]['guest_receive_ns']+=500;rows[-1]['guest_send_ns']+=500
        self.assertEqual(align(rows,100,0)['status'],'UNKNOWN')
        with self.assertRaises(ValueError):align(self.samples(),100,float('nan'))

    def test_extrapolation_labeled(self):
        result=align(self.samples(),10000,100)
        self.assertEqual(result['status'],'EXTRAPOLATED_CONDITIONAL')
        self.assertGreater(result['uncertainty_width_ns'],190)

    def test_task_identity_and_ticks(self):
        a=dict(pid=1,start_ticks=2,begin_ns=0,end_ns=1,schedstat=[5,5,1])
        b=dict(pid=1,start_ticks=2,begin_ns=2,end_ns=3,schedstat=[15,10,3])
        self.assertEqual(sched_delta(a,b)['runnable_wait_ns'],5)
        with self.assertRaises(ValueError):sched_delta(a,dict(b,start_ticks=3))


if __name__=='__main__':unittest.main()
