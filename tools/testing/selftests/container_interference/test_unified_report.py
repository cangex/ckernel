# SPDX-License-Identifier: GPL-2.0
import json
import unittest
import test_block_report
import test_counter_report
import test_net_report
import test_collector_manifest
import test_allocator_report
import test_allocator_lifetime
import test_block_tag_report
import test_block_merge_report
from owner_test import event
from unified_report import analyze,markdown


def encode(rows):
    terminal=[dict(session_id='7',kind=kind,detail=detail) for kind,detail in (
        ('terminal_counters','received=20 emitted=20 rejected=0'),('terminal_coverage','lost=0 owner_skipped=0'),
        ('terminal_scope','unknown=0 overdepth=0 unmatched=0 nested=0 expired=0 irq_context=0'),
        ('owner_entry_stages','owner_entries=0 sched_entries=0 target_waits=0 watch_events=0'))]
    return '\n'.join(json.dumps(v) for v in list(rows)+terminal).encode()


class UnifiedReport(unittest.TestCase):
    def test_background_billing_is_visible_without_fabricated_dirtier(self):
        f=test_block_report.BlockReport()
        result=analyze(f.record(),encode(f.async_rows(submitter_start=0,actor_start=0)))
        self.assertEqual(result['quality']['status'],'PASS',result)
        r=result['relations'][0]
        self.assertEqual(r['affected_actor'][:2],[0,0]); self.assertFalse(r['participants'])
        self.assertEqual(r['details']['selected_container'],[1,1])
        self.assertIsNone(r['details']['initial_dirtier']); self.assertIsNone(r['details']['inode_owner'])
        self.assertIn('按bio计费容器',markdown(result)); self.assertIn('启动代次未知',markdown(result))

    def test_block_sources_are_not_misreported_as_holders(self):
        f=test_block_merge_report.MergeReport(); f.setUp()
        result=analyze(f.record(),encode(f.appended()))
        self.assertEqual(result['quality']['status'],'PASS',result)
        r=result['relations'][0]
        self.assertFalse(r['participants'])
        self.assertEqual(r['details']['issue_bio_sources'][0]['remaining_bytes'],8192)
        self.assertEqual(len(r['details']['merge_transfers']),1)
        self.assertIn('未知 0 字节',markdown(result))
        self.assertIn('不表示设备存在唯一阻塞容器',markdown(result))

    def test_tag_wait_stays_e1_with_no_invented_holder(self):
        f=test_block_tag_report.TagReport()
        raw=encode([f.row(t,p) for t,p in ((10,1),(20,2),(30,3),(40,4))])
        result=analyze(test_block_report.BlockReport().record(),raw)
        self.assertEqual(result['quality']['status'],'PASS',result)
        relation=result['relations'][0]
        self.assertEqual(relation['relation'],'block_tag_wait')
        self.assertEqual(relation['evidence'],'E1')
        self.assertEqual(relation['participants'],[])
        self.assertEqual(relation['details']['sleep_intervals'][0]['interval_ns'],[20,30])
        self.assertIsNone(result['total_interference_ns'])

    def test_allocator_lifetime_failure_blocks_unified_acceptance(self):
        fixture=test_allocator_report.AllocatorReport()
        rows=fixture.rows([1,2,3,6,15,16,20])
        rows.append(test_allocator_lifetime.AllocationLifetime().sample(object_address=501))
        report=analyze(fixture.record(),encode(rows))
        self.assertEqual(report['quality']['status'],'FAIL')
        self.assertIn('allocation_lifetime_invalid',report['quality']['defects'])
        self.assertFalse(report['relations'])

    def test_allocator_without_stack_keeps_stages_not_call_chain(self):
        fixture=test_allocator_report.AllocatorReport()
        rows=fixture.rows()
        for row in rows: row['detail']=row['detail'].replace('stack_id=-1','stack_id=-17')
        report=analyze(fixture.record(),encode(rows))
        self.assertEqual(report['quality']['status'],'PASS',report)
        relation=report['relations'][0]
        self.assertEqual(relation['evidence'],'E1')
        self.assertFalse(relation['chain_leaf_to_root'])
        self.assertEqual(relation['details']['allocation_stack_error'],-17)
        self.assertIn('calling path unavailable',' '.join(relation['unknown']))

    def test_owner_family_requires_exact_scope_and_inventory(self):
        for collector,resource in (('owner',1),('fd',3),('slub',4)):
            record=test_counter_report.CounterReport().record(); record['collector']=collector
            record['inventory']=test_collector_manifest.CollectorContract().inventory(collector)
            rows=[dict(event(t,phase,who,resource=resource,cache=4096),session_id='7')
                  for t,phase,who in ((10,3,1),(20,2,2),(30,4,1),(40,3,2))]
            good=analyze(record,encode(rows))
            self.assertEqual(good['scope_audit']['status'],'PASS',good)
            self.assertEqual(len(good['relations']),1,good)
            incomplete=analyze(record,'\n'.join(json.dumps(r) for r in rows).encode())
            self.assertEqual(incomplete['quality']['status'],'BLOCKED')
            self.assertFalse(incomplete['relations'])
            record['inventory']['program_names']=['wrong']
            self.assertEqual(analyze(record,encode(rows))['quality']['status'],'FAIL')

    def test_counter_participants_never_become_lock_holders(self):
        fixture=test_counter_report.CounterReport()
        raw=encode(fixture.version2(fixture.call()+fixture.call(actor=2,start=30,leaf=101)))
        result=analyze(fixture.record(),raw)
        shared=[r for r in result['relations'] if r['relation']=='shared_updates']
        self.assertEqual(len(shared),1)
        self.assertEqual(shared[0]['evidence'],'E2')
        self.assertEqual(len(shared[0]['participants']),2)
        self.assertIsNone(shared[0]['affected_actor'])
        self.assertIsNone(result['total_interference_ns']); self.assertIn('JSON',markdown(result))

    def test_block_completion_is_not_memory_free_or_blocker(self):
        f=test_block_report.BlockReport()
        result=analyze(f.record(),encode([f.row(10,1),f.row(20,3),f.row(30,5,context=1)]))
        self.assertEqual(len(result['relations']),1)
        relation=result['relations'][0]
        self.assertEqual(relation['relation'],'block_request_episode')
        self.assertFalse(relation['participants'])
        self.assertEqual(relation['causal'],'NOT_ESTABLISHED')
        self.assertEqual(result['specialist']['requests'][0]['request_memory_free'],'UNOBSERVED')

    def test_bad_quality_rejects_unified_output(self):
        f=test_block_report.BlockReport(); record=f.record(); record['receipt']['dropped']=1
        result=analyze(record,encode([f.row(10,1),f.row(20,3),f.row(30,5)]))
        self.assertFalse(result['relations']); self.assertEqual(result['quality']['status'],'FAIL')

    def test_unknown_socket_holder_stays_e1(self):
        f=test_net_report.NetReport()
        raw=encode([f.row(10,2,who=0),f.row(20,1,who=2),f.row(30,3,who=0),
                    f.row(40,2,who=2),f.row(50,3,who=2)])
        result=analyze(f.record(),raw)
        self.assertEqual(result['quality']['status'],'PASS',result)
        relation=result['relations'][0]
        self.assertEqual(relation['evidence'],'E1')
        self.assertFalse(relation['participants'])
        self.assertIn('unknown container identity',' '.join(relation['unknown']))
