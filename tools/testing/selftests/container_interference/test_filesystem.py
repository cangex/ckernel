# SPDX-License-Identifier: GPL-2.0
import json
import unittest
from filesystem_report import analyze
from collector_manifest import contract
from periodic_plan import digest
from session import validate
from source_switches import expected_fields
import resource_policy
import test_collector_manifest
import test_prototype


class Filesystem(unittest.TestCase):
    def record(self):
        r=test_prototype.Explanations().record()
        r.update(collector='filesystem',filesystem_selection='/fs0',
                 collector_contract_sha256=digest(contract('filesystem')),
                 inventory=test_collector_manifest.CollectorContract().inventory('filesystem'))
        r['receipt']['producer_recursion']=dict(required=True,valid=True,skipped=0)
        return r

    def event(self,actor=1,begin=10,**updates):
        d=dict(protocol=1,begin_ns=begin,acquired_ns=0,end_ns=begin+3,tid=100+actor,
            task_start=1,cgroup_id=actor,cpu=0,resource=100,lease=7,dev=8<<20,operation=1,
            sample_shift=0,value=5,count=1,error=0,stack_id=-1)
        d.update(updates)
        return dict(kind='FILESYSTEM',id=actor,generation=1,detail=' '.join('%s=%s'%x for x in d.items()))

    def run_rows(self,rows,record=None,lease=7):
        tail=[('filesystem_source_filter','protocol=1 lease=%d dev=8388608 major=8 minor=0 pinned=1 readback=1'%lease),
              ('filesystem_source_filter_closed','lease=0 close_after_detach=1'),
              ('filesystem_native_audit','valid=1 entries=6 filtered=1 sampled=4 emitted=4 expired=0 recursive=0 endpoint_snapshot=1 unfinished_unknown=1'),
              ('terminal_counters','received=2 emitted=2 rejected=0'),
              ('terminal_coverage','lost=0 owner_skipped=0'),
              ('terminal_scope','unknown=0 overdepth=0 unmatched=0 nested=0 expired=0 irq_context=0'),
              ('owner_entry_stages','owner_entries=0 sched_entries=0 target_waits=0 watch_events=0')]
        rows=rows+[dict(kind=k,detail=v) for k,v in tail]
        raw='\n'.join(json.dumps(dict(row,session_id='7')) for row in rows).encode()
        return analyze(record or self.record(),raw)

    def test_journal_participation_not_blocker(self):
        r=self.run_rows([self.event(),self.event(actor=2,begin=30)])
        self.assertEqual(r['quality']['status'],'PASS')
        self.assertEqual(len(r['shared_resources']),1)
        self.assertEqual(r['coverage']['waits'],2)
        for e in r['episodes']:
            self.assertIsNone(e['holder']); self.assertIsNone(e['blocking_container'])

    def test_zero_wait_and_private_resources(self):
        r=self.run_rows([self.event(count=0),self.event(actor=2,begin=30,resource=200,count=0)])
        self.assertEqual(r['quality']['status'],'PASS')
        self.assertEqual(r['coverage']['waits'],0); self.assertFalse(r['shared_resources'])

    def test_unified_report_retains_parser_provenance(self):
        from unittest.mock import patch
        from unified_report import analyze as unified
        report=self.run_rows([self.event()])
        self.assertIn('filesystem_report',report['analysis_source_sha256'])
        with patch('filesystem_report.analyze',return_value=report), patch('unified_report.explain',return_value=dict(
                quality=report['quality'],source=report['source'],analysis_source_sha256={},explanation_lag_ns=None)):
            r=unified(self.record(),b'')
        self.assertEqual(r['quality']['status'],'PASS')
        self.assertIn('filesystem_report',r['analysis_source_sha256'])
        self.assertEqual(r['relations'][0]['causal'],'NOT_ESTABLISHED')

    def test_other_fs_lease_reuse_unknown_and_window(self):
        for e in (self.event(lease=8),self.event(dev=9<<20),self.event(actor=3),self.event(begin=99),self.event(sample_shift=4)):
            r=self.run_rows([e]); self.assertNotEqual(r['quality']['status'],'PASS')
            self.assertFalse(r['shared_resources'])

    def test_group_and_orphan_features_not_a_holder(self):
        rows=[self.event(operation=3,sample_shift=4),self.event(actor=2,begin=30,operation=3,sample_shift=4),
              self.event(begin=40,operation=4,sample_shift=4,acquired_ns=41),
              self.event(begin=50,operation=6,sample_shift=4,count=2)]
        r=self.run_rows(rows)
        self.assertEqual(r['quality']['status'],'PASS')
        self.assertEqual(r['coverage']['waits'],0)
        self.assertEqual(r['shared_resources'][0]['resource']['kind'],'allocation_group')
        self.assertTrue(all(e['lock_contention']=='NOT_ESTABLISHED' for e in r['episodes']))

    def test_duplicate_and_partial_rejected(self):
        self.assertEqual(self.run_rows([self.event(),self.event()])['quality']['status'],'FAIL')
        r=self.record(); r['result']='PARTIAL'
        self.assertFalse(self.run_rows([self.event(),self.event(actor=2,begin=30)],r)['shared_resources'])
        self.assertEqual(self.run_rows([])['coverage']['observation_status'],'NO_ACCEPTED_SAMPLES')

    def test_admission_requires_explicit_fs_and_source_version(self):
        req=dict(version=1,op='start',collector='filesystem',targets=['1'],nonce='test',filesystem='/fs0')
        validate(req)
        for p in (None,'relative','/x\0y',3):
            with self.assertRaises(ValueError): validate(dict(req,filesystem=p))
        with self.assertRaises(ValueError): validate(dict(req,collector='reclaim'))
        self.assertEqual(expected_fields('17','filesystem')['filesystem'],'1')
        self.assertEqual(expected_fields('17',None)['filesystem_filter'],'0')
        with self.assertRaises(ValueError): expected_fields('16','filesystem')
        with self.assertRaises(PermissionError): resource_policy.admit(resource_policy.policy(),'filesystem',automatic=True)
