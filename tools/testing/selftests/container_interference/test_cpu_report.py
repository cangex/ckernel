# SPDX-License-Identifier: GPL-2.0
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'container_interference'))
from collector_manifest import contract
from periodic_plan import digest
from cpu_report import analyze,timeline,union
from session import validate,worker_roots
from source_switches import expected_fields
import resource_policy
import test_collector_manifest
import test_prototype


def point(t,phase=1,actor=1,next_actor=2,cpu=0,**kw):
    r=dict(protocol=2,time_ns=t,cpu=cpu,phase=phase,tid=actor*100,task_start=actor,
        actor_id=actor,actor_generation=int(bool(actor)),next_tid=next_actor*100,next_start=next_actor,
        next_id=next_actor,next_generation=int(bool(next_actor)),value=0,flags=1,destination=0,object=0,function=0,
        irq_ns=0,irq_entries=0,irq_errors=0,irq_valid=1)
    if phase!=1:
        for k in ('next_tid','next_start','next_id','next_generation'): r[k]=0
        r['flags']=0
    r.update(kw); return r


class CPUReport(unittest.TestCase):
    def record(self):
        r=test_prototype.Explanations().record()
        r.update(collector='cpu',cpu_selection=[0],collector_contract_sha256=digest(contract('cpu')),
            inventory=test_collector_manifest.CollectorContract().inventory('cpu'))
        r['receipt']['producer_recursion']=dict(required=True,valid=True,skipped=0)
        return r

    def analyze(self,points,record=None):
        tail=[('cpu_selection','cpu=0 count=1 readback=1'),
              ('cpu_irq_audit','protocol=2 cpu=0 total_ns=15 entries=2 errors=0 depth=0 sequence=8 detached=1'),
              ('terminal_counters','received=20 emitted=20 rejected=0'),
              ('terminal_coverage','lost=0 owner_skipped=0'),
              ('terminal_scope','unknown=0 overdepth=0 unmatched=0 nested=0 expired=0 irq_context=0'),
              ('owner_entry_stages','owner_entries=0 sched_entries=0 target_waits=0 watch_events=0')]
        rows=[dict(kind='CPU_POINT',detail=' '.join('%s=%s'%v for v in p.items())) for p in points]
        rows += [dict(kind=k,detail=v) for k,v in tail]
        return analyze(record or self.record(),'\n'.join(json.dumps(dict(r,session_id='7')) for r in rows).encode())

    def test_same_cpu_not_causal(self):
        r=self.analyze([point(10),point(40,actor=2,next_actor=1),point(60)])
        self.assertEqual(r['quality']['status'],'PASS')
        self.assertEqual(len(r['associations']),2)
        self.assertIsNone(r['associations'][0]['blocking_container'])
        self.assertEqual(r['associations'][0]['end_ns']-r['associations'][0]['begin_ns'],30)

    def test_separate_cpus_no_relation(self):
        r=timeline([point(10,next_actor=0),point(20,actor=0,next_actor=1),
                    point(10,actor=2,next_actor=0,cpu=1),point(20,actor=0,next_actor=2,cpu=1)],{0,1})
        self.assertFalse(r['associations'])

    def test_migration_invalidates_join(self):
        r=self.analyze([point(10),point(20,phase=2,destination=1),point(40,actor=2,next_actor=1)])
        self.assertFalse(r['associations']); self.assertEqual(r['unknown']['migrated_wait'],1)

    def test_task_reuse_not_joined(self):
        r=self.analyze([point(10),point(40,actor=2,next_actor=1,next_start=99)])
        self.assertFalse(r['associations'])

    def test_interrupt_union_not_double_counted(self):
        p=[point(10),point(40,actor=2,next_actor=1,irq_ns=15,irq_entries=2)]
        r=self.analyze(p); self.assertEqual(r['quality']['status'],'PASS')
        self.assertEqual(r['execution'][0]['observed_interrupt_ns'],15)
        self.assertEqual(r['execution'][0]['irq_subtracted_slice_ns'],15)
        r=self.analyze([point(10),point(40,actor=2,next_actor=1,irq_errors=1)])
        self.assertIsNone(r['execution'][0]['irq_subtracted_slice_ns'])

    def test_work_executor_not_origin(self):
        p=[point(10,next_actor=0,next_tid=50,next_start=7),
           point(15,phase=8,actor=0,tid=50,task_start=7,object=123,function=456),
           point(30,phase=9,actor=0,tid=50,task_start=7,object=123,function=456),
           point(40,actor=0,tid=50,task_start=7,next_actor=1)]
        r=self.analyze(p); self.assertEqual(r['quality']['status'],'PASS')
        self.assertEqual(r['background'][0]['observed_irq_subtracted_execution_ns'],15)
        self.assertIsNone(r['background'][0]['origin'])

    def test_gap_partial_and_reuse_fail_closed(self):
        self.assertFalse(self.analyze([point(10),point(40,actor=1)])['associations'])
        p=[point(10,phase=8,object=123,function=456),point(30,phase=9,object=123,function=789)]
        self.assertEqual(self.analyze(p)['quality']['status'],'FAIL')
        self.assertFalse(self.analyze([point(10,phase=9,object=123,function=456)])['background'])

    def test_quality_wrong_cpu_and_duplicate(self):
        for p in ([point(10,cpu=1)],[point(10),point(10)],[point(100)],[point(10,actor=3)]):
            self.assertEqual(self.analyze(p)['quality']['status'],'FAIL')
        r=self.record(); r['result']='PARTIAL'
        self.assertFalse(self.analyze([point(10),point(40,actor=2,next_actor=1)],r)['associations'])

    def test_native_wait_separate(self):
        r=self.analyze([point(10),point(39,phase=3,value=29),point(40,actor=2,next_actor=1)])
        self.assertFalse(r['native_sched_wait'][0]['additive'])

    def test_quota_is_boundary_fact_not_neighbor_blame(self):
        r=self.record(); key=next(iter(r['root_identities'])); ident=r['root_identities'][key]
        def snap(t,n):
            return dict(id=ident['id'],generation=ident['generation'],identity_valid=True,
                config={'cpu.max':'20000 100000'},files={'cpu.stat':dict(start_ns=t,end_ns=t+1,
                    counters=dict(nr_throttled=n,throttled_usec=n*100))})
        r['boundary_before']={key:snap(1,0)}; r['boundary_after']={key:snap(101,2)}
        q=self.analyze([point(10),point(40,actor=2,next_actor=1)],r)['quota_observations'][0]
        self.assertEqual(q['nr_throttled'],2); self.assertIsNone(q['blocking_container'])
        self.assertFalse(q['perf_window_aligned'])
        r['boundary_after'][key]['config']['cpu.max']='max 100000'
        self.assertFalse(self.analyze([],r)['quota_observations'])

    def test_unified_dispatch_keeps_noncausal_boundaries(self):
        from unittest.mock import patch
        from unified_report import analyze as unified
        report=self.analyze([point(10),point(40,actor=2,next_actor=1)])
        with patch('cpu_report.analyze',return_value=report), patch('unified_report.explain',return_value=dict(
                quality=report['quality'],source=report['source'],analysis_source_sha256={},explanation_lag_ns=None)):
            r=unified(self.record(),b'')
        self.assertEqual(r['relations'][0]['relation'],'cpu_execution_overlap')
        self.assertEqual(r['relations'][0]['causal'],'NOT_ESTABLISHED')

    def test_selection_and_contract(self):
        req=dict(version=1,op='start',collector='cpu',cpus=[0,1],targets=['1'],nonce='test')
        validate(req)
        for cpus in (None,[],[True],[512],[-1],[0,0],[{}],list(range(9))):
            with self.assertRaises(ValueError): validate(dict(req,cpus=cpus))
        with self.assertRaises(ValueError): validate(dict(req,collector='ip'))
        self.assertEqual(set(worker_roots({'1':{},'2':{}},['1'],'cpu')),{'1','2'})
        self.assertEqual(expected_fields('20','cpu')['work_begin'],'1')
        self.assertEqual(expected_fields('20','owner')['sched_switch'],'1')
        with self.assertRaises(ValueError): expected_fields('19','cpu')
        with self.assertRaises(PermissionError): resource_policy.admit(resource_policy.policy(),'cpu',automatic=True)
        self.assertNotIn('stacks',contract('cpu')['maps'])
        self.assertEqual(union([(1,3),(2,4),(6,7)]),[[1,4],[6,7]])
