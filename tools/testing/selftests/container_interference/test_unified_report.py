# SPDX-License-Identifier: GPL-2.0
import json
import unittest
import test_block_report
import test_counter_report
from unified_report import analyze,markdown


def encode(rows):
    terminal=[dict(session_id='7',kind=kind,detail=detail) for kind,detail in (
        ('terminal_counters','received=20 emitted=20 rejected=0'),('terminal_coverage','lost=0 owner_skipped=0'),
        ('terminal_scope','unknown=0 overdepth=0 unmatched=0 nested=0 expired=0 irq_context=0'),
        ('owner_entry_stages','owner_entries=0 sched_entries=0 target_waits=0 watch_events=0'))]
    return '\n'.join(json.dumps(v) for v in list(rows)+terminal).encode()


class UnifiedReport(unittest.TestCase):
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
