# SPDX-License-Identifier: GPL-2.0
import copy
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'container_interference'))
from prototype_contract import assess,STAGES,CONTROLS


class PrototypeContract(unittest.TestCase):
    def rows(self):
        rows=[dict(name=k,capability=k,status='PASS_SCOPED',checked=dict(source=dict(kernel_notes_sha256='kernel')))
              for k in sorted({k for values in STAGES.values() for k in values})]
        by={e['capability']:e for e in rows}
        by['control']['checked']['checks']=[dict(name=k,status='PASS') for k in CONTROLS]
        by['routing']['checked'].update(records=10,automatic=2,manual=1,discovery_timing=[{},{}],
            reports={str(i):dict(timing=dict(explanation_boundary='unified_analysis_complete_before_serialization',
                same_clock_as_capture=True,explanation_lag_ns=25)) for i in range(10)})
        by['joint']['checked']['states']=[dict(mode='off')]*33
        slub=copy.deepcopy(by['joint']); slub['name']='slub-joint'
        slub['checked']['states']=[dict(mode=m) for m in ('off','slub') for _ in range(3)]
        rows.append(slub)
        by['rwsem_joint']['checked']['states']=[{}]*60
        by['mixed']['checked']['states']=[{}]*24
        return rows

    def test_scoped_completion_never_accepts_production_or_universal_coverage(self):
        result=assess(self.rows())
        self.assertTrue(result['x7_complete'])
        self.assertEqual(result['status'],'PASS_SCOPED')
        self.assertFalse(result['production_accepted'])
        self.assertFalse(result['full_linux_coverage'])

    def test_empty_partial_failed_and_guard_only_inputs_are_incomplete(self):
        self.assertFalse(assess([])['x7_complete'])
        rows=self.rows()
        for key in ('net_release','net','rwsem_joint','fd_relations'):
            partial=[e for e in rows if e['capability']!=key]
            self.assertFalse(assess(partial)['x7_complete'])
        rows[-1]['status']='FAIL'
        self.assertFalse(assess(rows)['x7_complete'])

    def test_historical_timing_and_old_kernel_joint_cannot_close_release(self):
        rows=self.rows(); route=next(e for e in rows if e['capability']=='routing')
        route['checked']['reports']['0']['timing']['explanation_boundary']='legacy_base_summary_only'
        self.assertFalse(assess(rows)['x7_complete'])
        rows=self.rows(); next(e for e in rows if e['capability']=='rwsem_joint')['checked']['source']['kernel_notes_sha256']='old'
        result=assess(rows)
        self.assertFalse(result['x7_complete'])
        self.assertIn('same_kernel',result['stages']['X7']['missing'][0])

    def test_missing_fault_controls_or_zero_latency_are_not_silent_passes(self):
        rows=self.rows(); control=next(e for e in rows if e['capability']=='control')
        control['checked']['checks']=[r for r in control['checked']['checks'] if r['name']!='failed_verification_blocks_admission']
        self.assertFalse(assess(rows)['x7_complete'])
        rows=self.rows(); next(e for e in rows if e['capability']=='routing')['checked']['reports']['0']['timing']['explanation_lag_ns']=None
        self.assertFalse(assess(rows)['x7_complete'])
