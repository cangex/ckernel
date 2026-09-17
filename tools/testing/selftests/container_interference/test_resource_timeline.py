# SPDX-License-Identifier: GPL-2.0
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]/'container_interference'))
from resource_timeline import analyze, counter_delta, cpu_bounds


class ResourceTimeline(unittest.TestCase):
    def fixture(self):
        return dict(schema='cis-resource-timeline-v1', mode='ip', timer_control='default',
                    sampler_thread_cpu_ns=100, stages=dict(before_start_ns=0, daemon_exit_ns=1_000_000_000,
                                                         tail_end_ns=6_000_000_000),
                    samples=[dict(time_ns=t, errors=[], observer=dict(memory_current=c,
                              memory_peak=p, cpu_stat={'usage_usec':i*100}, memory_events={'oom':0}))
                             for i,(t,c,p) in enumerate([(0,0,0),(1_500_000_000,20,200),
                                                         (6_000_000_001,10,200)])])

    def test_charge_is_not_total(self):
        value=analyze(self.fixture())
        self.assertEqual(value['accounted_memory_peak_bytes'],200)
        self.assertEqual(value['sampled_charge_peak_bytes'],20)
        self.assertFalse(value['total_memory_complete'])
        self.assertFalse(value['background_cpu_complete'])

    def test_bad_snapshot_refused(self):
        for key in ('errors','peak','tail'):
            value=self.fixture()
            if key=='errors': value['samples'][1]['errors']=['read failed']
            if key=='peak': value['samples'][-1]['observer']['memory_peak']=1
            if key=='tail': value['stages']['tail_end_ns']=2_000_000_000
            with self.assertRaises(ValueError): analyze(value)

    def test_reset_and_changed_counter_set(self):
        for first,last in [({'x':2},{'x':1}),({'x':1},{'y':2}),({'x':-1},{'x':1})]:
            with self.assertRaises(ValueError): counter_delta(first,last)

    def test_stage_cpu_is_bracketed_not_interpolated(self):
        rows=[dict(time_ns=t,end_ns=t+1,observer={'cpu_stat':{'usage_usec':v}})
              for t,v in [(0,0),(10,100),(20,140),(30,200)]]
        bounds=cpu_bounds(rows,5,25)
        self.assertEqual((bounds['lower_usec'],bounds['upper_usec']),(40,200))
        self.assertEqual(cpu_bounds(rows,0,25)['status'],'UNKNOWN')
        with self.assertRaises(ValueError):cpu_bounds(rows,25,0)


if __name__=='__main__': unittest.main()
