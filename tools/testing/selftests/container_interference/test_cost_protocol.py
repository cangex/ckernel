# SPDX-License-Identifier: GPL-2.0
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'container_interference'))
from session_check import cost_protocol


class CostProtocol(unittest.TestCase):
    def inputs(self):
        header=dict(version=2,pairs=5,warmup_operations=4096,window_ms=2000,
                    timer_slack='inherited_default',arrival_rate=2000,no_tracing=True,
                    diagnostic_window_p99_target_pct=2)
        files={'cost-%s-%d-%s-%d.log'%(w,r,m,role):
               'CIS_WARMUP operations=4096 end_ns=100 before_start=1\nCIS_RESULT start_ns=200'
               for w in ('throughput','latency') for r in range(5)
               for m in ('off','idle','ip','owner') for role in range(2)}
        return 'CIS_PROFILE_COST_PROTOCOL '+json.dumps(header),files

    def test_frozen_and_legacy(self):
        header,files=self.inputs()
        self.assertEqual(cost_protocol(header,files)['version'],2)
        self.assertEqual(cost_protocol('',{})['version'],1)

    def test_incomplete_late_traced_refused(self):
        for mode in ('missing','late','trace'):
            header,files=self.inputs();key=next(iter(files))
            if mode=='missing':files.pop(key)
            if mode=='late':files[key]=files[key].replace('end_ns=100','end_ns=300')
            if mode=='trace':files[key]+='\nCIS_LATENCY_SAMPLE index=0'
            with self.assertRaises(ValueError):cost_protocol(header,files)


if __name__=='__main__':unittest.main()
