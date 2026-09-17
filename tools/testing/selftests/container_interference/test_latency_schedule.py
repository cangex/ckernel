# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]/'container_interference'))
from latency_schedule import analyze


class LatencySchedule(unittest.TestCase):
    workload='''CIS_LATENCY_TIMELINE count=1 post_window_export=1 clock=guest_monotonic
CIS_LATENCY_SAMPLE index=0 due_ns=1000000000 begin_ns=1000060000 finish_ns=1000065000
CIS_LATENCY count=1 p99_ns=65000 max_ns=65000 rate=2000 start_ns=1000000000 end_ns=1000065000
'''
    trace=''' idle-0 [000] d..2 1.000050: sched_waking: comm=work pid=123 prio=120 target_cpu=000
 idle-0 [000] d..2 1.000055: sched_switch: prev_comm=idle prev_pid=0 prev_state=R ==> next_comm=work next_pid=123
'''

    def meta(self):
        return dict(clock='mono',diagnostic_only=True,host_pids=[123],truncated=False,
                    cpu_stats={'cpu0':{'overrun':0,'commit overrun':0,'dropped events':0}})

    def test_join_decomposes_not_cause(self):
        value=analyze(self.workload,self.trace,self.meta(),123)
        self.assertEqual(value['observed'],1)
        self.assertEqual(value['text_resolution_ns'],1000)
        self.assertEqual(value['selected_largest_requests'][0]['waking_to_running_ns'],5000)
        self.assertEqual(value['selected_largest_requests'][0]['due_to_waking_ns'],50000)
        self.assertTrue(value['diagnostic_only'])

    def test_duplicate_wakes_unknown(self):
        value=analyze(self.workload,self.trace+self.trace.splitlines()[0],self.meta(),123)
        self.assertEqual(value['unknown'],1)

    def test_loss_clock_unknown_pid_refused(self):
        for kind in ('loss','clock','pid','missing','truncated'):
            meta=self.meta();pid=123
            if kind=='loss':meta['cpu_stats']['cpu0']['overrun']=1
            if kind=='clock':meta['clock']='local'
            if kind=='pid':pid=124
            if kind=='missing':del meta['cpu_stats']['cpu0']['dropped events']
            if kind=='truncated':meta['truncated']=True
            with self.assertRaises(ValueError):analyze(self.workload,self.trace,meta,pid)

    def test_wake_before_request_not_reused(self):
        trace=self.trace.replace('1.000050','0.999000')
        value=analyze(self.workload,trace,self.meta(),123)
        self.assertEqual(value['unknown'],1)


if __name__=='__main__':unittest.main()
