# SPDX-License-Identifier: GPL-2.0
import json
import unittest
import test_block_report
import test_counter_report
import test_net_report
import test_collector_manifest
from owner_test import event
from unified_report import analyze,markdown


def encode(rows):
    terminal=[dict(session_id='7',kind=kind,detail=detail) for kind,detail in (
        ('terminal_counters','received=20 emitted=20 rejected=0'),('terminal_coverage','lost=0 owner_skipped=0'),
        ('terminal_scope','unknown=0 overdepth=0 unmatched=0 nested=0 expired=0 irq_context=0'),
        ('owner_entry_stages','owner_entries=0 sched_entries=0 target_waits=0 watch_events=0'))]
    return '\n'.join(json.dumps(v) for v in list(rows)+terminal).encode()


class UnifiedReport(unittest.TestCase):
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
