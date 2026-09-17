#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'container_interference'))
from observer_cost import analyze as component
from control_cost import analyze as control
from overhead import interval, analyze as overhead
from cost_snapshots import parse as snapshots


class CostReports(unittest.TestCase):
    def test_system_snapshots_preserve_units_and_unknown_ownership(self):
        lines=[]
        for phase, value in [('start',10),('end',20)]:
            lines += [f'CIS_SNAPSHOT {phase} /proc/stat',
                      'cpu '+' '.join([str(value)]*10), 'cpu0 '+' '.join([str(value)]*10),
                      'CIS_SNAPSHOT_END', f'CIS_SNAPSHOT {phase} /sys/fs/cgroup/cis-monitor/memory.current',
                      str(value), 'CIS_SNAPSHOT_END']
        r=snapshots(lines)
        self.assertFalse(r['quality_errors'])
        self.assertEqual(r['cpu_delta_ticks']['cpu0']['system'],10)
        self.assertEqual(r['observer_cgroup_memory_start_end_bytes'],[10,20])
        self.assertFalse(r['exclusive_observer_cpu_known'])

    def test_missing_and_truncated_snapshots_are_not_zero(self):
        self.assertTrue(snapshots([])['quality_errors'])
        self.assertTrue(snapshots(['CIS_SNAPSHOT start /proc/stat','cpu 1 2'])['quality_errors'])

    def test_empty_and_qmp_only_are_not_evidence(self):
        text='{"event":"SHUTDOWN"}\n'
        self.assertFalse(component(text)['screen_numeric_pass'])
        self.assertFalse(control(text)['process_and_coverage_pass'])
        self.assertFalse(overhead(text,10,('ip',),True)['pass'])

    def test_fixed_pair_size_is_explicit(self):
        self.assertEqual(interval([1]*10),[1,1])
        self.assertEqual(interval([1]*9),[None,None])

    def test_control_detachment_cannot_be_hidden_by_idle_metrics(self):
        begin='CIS_FLEET_BEGIN count=128 mode=ip workload=idle duration=15 target=0 start_ns=2000000000 cpus=64 observer_pid=8'
        disabled={'version':1,'time_ns':3000000000,'id':0,'generation':0,
                  'kind':'budget_disable','detail':'collectors detached'}
        text='\n'.join(['CIS_FILE /tmp/control-128-ip.log',begin,'CIS_FLEET_END result=PASS',
                        'CIS_FILE /tmp/observer-8.jsonl',json.dumps(disabled,separators=(',',':')),
                        'CIS_R2_CONTROL_FAILURES=0'])
        result=control(text)
        self.assertFalse(result['process_and_coverage_pass'])
        self.assertTrue(any(isinstance(x,dict) and x['event']['kind']=='budget_disable' for x in result['failures']))


if __name__=='__main__': unittest.main()
