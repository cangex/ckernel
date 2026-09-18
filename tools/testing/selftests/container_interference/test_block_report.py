# SPDX-License-Identifier: GPL-2.0
import json
import unittest
import test_counter_report
import test_collector_manifest
from block_report import analyze


class BlockReport(unittest.TestCase):
    def record(self):
        r=test_counter_report.CounterReport().record(); r['collector']='block'
        r['inventory']=test_collector_manifest.CollectorContract().inventory('block')
        return r

    def row(self,time,phase,epoch=10,request=1000,who=1,context=0,**changes):
        d=dict(protocol=1,sample_time_ns=time,request=request,episode_ns=epoch,submitter_tid=who+100,
            submitter_start=1,queue=2000,bio=3000,phase=phase,dev_major=8,dev_minor=0,
            remaining=4096,completed=4096 if phase==5 else 0,operation=1,multi_bio=0,context=context,status=0,
            actor_id=who if not context else 0,actor_generation=1 if not context else 0,
            actor_tid=who+100 if not context else 0,actor_start=1 if not context else 0,cpu=0,stack_id=-1)
        d.update(changes)
        return dict(session_id='7',kind='BLOCK',id=who,generation=1,detail=' '.join('%s=%s'%p for p in d.items()))

    def run_rows(self,rows,record=None):
        rows=list(rows)
        for kind,detail in (
            ('terminal_counters','received=20 emitted=20 rejected=0'),
            ('terminal_coverage','lost=0 owner_skipped=0'),
            ('terminal_scope','unknown=0 overdepth=0 unmatched=0 nested=0 expired=0 irq_context=0'),
            ('owner_entry_stages','owner_entries=0 sched_entries=0 target_waits=0 watch_events=0')):
            rows.append(dict(session_id='7',kind=kind,detail=detail))
        return analyze(record or self.record(),'\n'.join(json.dumps(r) for r in rows).encode())

    def test_partial_completion_retains_episode_and_irq_is_not_owner(self):
        r=self.run_rows([self.row(10,1),self.row(20,2),self.row(30,3),
            self.row(40,5,completed=1024,context=2),self.row(50,5,remaining=3072,completed=3072,context=1)])
        self.assertEqual(r['quality']['status'],'PASS',r)
        req=r['requests'][0]
        self.assertEqual(req['queue_intervals_ns'],[[20,30]])
        self.assertEqual(req['service_intervals'],[dict(interval_ns=[30,50],end='data_completion')])
        self.assertEqual(len(req['completions']),2)
        self.assertIsNone(req['completions'][0]['executor']); self.assertIsNone(req['blocking_container'])
        self.assertEqual(req['request_memory_free'],'UNOBSERVED')

    def test_requeue_keeps_disjoint_service_and_queue_intervals(self):
        r=self.run_rows([self.row(10,1),self.row(20,3),self.row(30,4),self.row(40,2),self.row(50,3),self.row(60,5)])
        req=r['requests'][0]
        self.assertEqual(req['queue_intervals_ns'],[[40,50]])
        self.assertEqual([v['interval_ns'] for v in req['service_intervals']],[[20,30],[50,60]])

    def test_merge_and_multibio_do_not_transfer_owner_to_survivor(self):
        r=self.run_rows([self.row(10,1),self.row(20,2,multi_bio=1),self.row(30,6,multi_bio=1)])
        req=r['requests'][0]
        self.assertEqual(req['terminal'],'merge_transfer'); self.assertEqual(req['ownership'],'initial_submitter_only')
        self.assertIn('merged_into_unobserved_survivor',req['uncertainty'])

    def test_remap_is_not_another_blocker(self):
        r=self.run_rows([self.row(10,1),self.row(20,7,dev_minor=16),self.row(30,3,dev_minor=16),self.row(40,5,dev_minor=16)])
        req=r['requests'][0]
        self.assertEqual(req['ownership'],'initial_submitter_only'); self.assertIsNone(req['blocking_container'])
        self.assertIn('route_changed',req['uncertainty'])

    def test_pointer_reuse_requires_disjoint_episodes(self):
        first=[self.row(10,1),self.row(20,3),self.row(40,5)]
        for epoch,status in ((50,'PASS'),(30,'FAIL')):
            r=self.run_rows(first+[self.row(epoch,1,epoch=epoch,who=2),self.row(epoch+5,3,epoch=epoch,who=2),self.row(epoch+10,5,epoch=epoch,who=2)])
            self.assertEqual(r['quality']['status'],status,r)
            if status=='PASS': self.assertEqual(len(r['requests']),2)

    def test_invalid_completion_actor_or_missing_start_rejects(self):
        for rows in ([self.row(10,1),self.row(20,3),self.row(30,5,completed=8192)],
                     [self.row(10,1),self.row(20,3),self.row(30,5,context=1,actor_id=1)],
                     [self.row(20,3),self.row(30,5)],
                     [self.row(10,1),self.row(20,3),self.row(30,5),self.row(40,5)]):
            r=self.run_rows(rows); self.assertEqual(r['quality']['status'],'FAIL',r); self.assertFalse(r['requests'])

    def test_private_devices_never_create_edges(self):
        rows=[self.row(10,1),self.row(20,3),self.row(50,5)]
        rows.extend([self.row(15,1,epoch=15,request=2000,who=2,dev_minor=16),
            self.row(25,3,epoch=15,request=2000,who=2,dev_minor=16),self.row(55,5,epoch=15,request=2000,who=2,dev_minor=16)])
        r=self.run_rows(rows); self.assertEqual(len(r['requests']),2)
        self.assertTrue(all(x['blocking_container'] is None for x in r['requests']))

    def test_unclosed_and_stack_failure_are_explicit_not_zero(self):
        r=self.run_rows([self.row(10,1),self.row(20,3,stack_id=-17)])
        req=r['requests'][0]
        self.assertEqual(req['terminal'],'UNOBSERVED'); self.assertIsNone(req['episode_interval_ns'][1])
        self.assertIn('window_unclosed_request',req['uncertainty']); self.assertIn('-17',r['stack_capture_errors'])

    def test_quality_failure_suppresses_relations(self):
        record=self.record(); record['receipt']['producer_recursion']['skipped']=1
        r=self.run_rows([self.row(10,1),self.row(20,3),self.row(30,5)],record)
        self.assertEqual(r['quality']['status'],'FAIL'); self.assertFalse(r['requests'])

    def test_bio_cgroup_is_distinct_from_submitter_and_irq_executor(self):
        def row(time,phase,**changes):
            return self.row(time,phase,protocol=2,bio_cgroup=2,bio_owner_id=2,bio_owner_generation=1,
                bio_bytes=4096,bio_origin_overdepth=0,**changes)
        r=self.run_rows([row(10,1),row(20,3),row(30,5,context=1)])
        self.assertEqual(r['quality']['status'],'PASS',r)
        req=r['requests'][0]
        self.assertEqual(req['submitter'][0],1)
        self.assertEqual(req['head_bio_origins'][0]['registered_container'],[2,1])
        self.assertIsNone(req['completions'][0]['executor'])
        self.assertEqual(req['origin_coverage'],'observed_head_bio_only')
        self.assertIsNone(req['blocking_container'])

    def test_bio_origin_unknown_and_generation_mismatch(self):
        def rows(owner):
            return [self.row(t,p,protocol=2,bio_cgroup=9,bio_owner_id=owner,bio_owner_generation=1 if owner else 0,
                bio_bytes=4096,bio_origin_overdepth=0) for t,p in ((10,1),(20,3),(30,5))]
        unknown=self.run_rows(rows(0)); self.assertEqual(unknown['quality']['status'],'PASS')
        self.assertIsNone(unknown['requests'][0]['head_bio_origins'][0]['registered_container'])
        self.assertIn('head_bio_origin_unresolved',unknown['requests'][0]['uncertainty'])
        wrong=self.run_rows(rows(9)); self.assertEqual(wrong['quality']['status'],'FAIL'); self.assertFalse(wrong['requests'])
