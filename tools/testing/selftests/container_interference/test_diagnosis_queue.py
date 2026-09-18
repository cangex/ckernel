# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'container_interference'))
from diagnosis_queue import DiagnosisQueue,NS
from diagnosis_plan import recommend


class DiagnosisQueueTests(unittest.TestCase):
    def setUp(self): self.time=100*NS; self.q=DiagnosisQueue(lambda:self.time); self.roots={'1:1','2:1','3:1','4:1'}
    def proposal(self,root='1:1',collector='counter',sid='7'):
        return dict(target=root,collector=collector,source_session=sid,source_end_ns=self.time,source_epoch=1,automatic_eligible=True)
    def offer(self,*args): return self.q.offer(self.proposal(*args),self.roots,1)

    def test_default_off_manual_needs_live_validated_collector(self):
        key=self.offer()
        self.assertIsNone(self.q.select(self.roots,1,{'counter'},automatic=True))
        self.assertIsNone(self.q.select(self.roots,1,set(),candidate_id=key))
        item=self.q.select(self.roots,1,{'counter'},candidate_id=key)
        self.assertFalse(item['automatic']); self.q.admitted(item)
        self.assertFalse(self.q.items)

    def test_shared_automatic_budget_and_ordinary_interleave(self):
        self.q.enabled=True; self.offer(); self.offer('2:1')
        self.q.admitted(self.q.select(self.roots,1,{'counter'},automatic=True))
        self.assertIsNone(self.q.select(self.roots,1,{'counter'},automatic=True))
        self.q.ordinary_admitted(); self.q.admitted(self.q.select(self.roots,1,{'counter'},automatic=True))
        self.q.ordinary_admitted(); self.offer('3:1')
        self.assertIsNone(self.q.select(self.roots,1,{'counter'},automatic=True))
        restored=DiagnosisQueue(lambda:self.time,self.q.ledger())
        self.assertEqual(restored.auto_started,2); self.assertFalse(restored.enabled); self.assertFalse(restored.items)

    def test_cooldown_fairness_and_stale_candidates(self):
        self.offer(); self.q.admitted(self.q.select(self.roots,1,{'counter'}))
        self.offer('1:1','counter','8'); self.offer('2:1','counter','9')
        self.assertEqual(self.q.select(self.roots,1,{'counter'})['target'],'2:1')
        self.time+=301*NS; self.assertIsNone(self.q.select(self.roots,1,{'counter'}))
        self.assertEqual(self.q.skipped['expired'],2)

    def test_epoch_unregister_capacity_and_duplicates(self):
        self.offer(); self.assertIsNone(self.offer()); self.assertEqual(len(self.q.items),1)
        self.q.prune(self.roots,2); self.assertFalse(self.q.items)
        self.offer(); self.q.prune({'2:1'},1); self.assertFalse(self.q.items)
        for root in self.roots:
            self.offer(root); self.offer(root,'net')
        self.assertIsNone(self.offer('1:1','block')); self.assertEqual(len(self.q.items),8)

    def test_invalid_generation_future_and_restart_ledger(self):
        for change in (dict(source_end_ns=self.time+1),dict(source_epoch=2),dict(target='1:2'),dict(collector='ip')):
            p=self.proposal(); p.update(change)
            with self.assertRaises(ValueError): self.q.offer(p,self.roots,1)
        with self.assertRaises(ValueError): DiagnosisQueue(lambda:self.time,dict(auto_started=3))

    def test_normal_hotspot_is_manual_only(self):
        p=self.proposal(); p['automatic_eligible']=False
        self.q.offer(p,self.roots,1); self.q.enabled=True
        self.assertIsNone(self.q.select(self.roots,1,{'counter'},automatic=True))
        self.assertIsNotNone(self.q.select(self.roots,1,{'counter'}))

    def test_new_evidence_refreshes_both_eligibility_directions(self):
        p=self.proposal(); p['automatic_eligible']=False
        old=self.q.offer(p,self.roots,1); first=self.time
        self.time+=NS; new=self.offer('1:1','counter','8'); self.q.enabled=True
        self.assertNotEqual(old,new); self.assertNotIn(old,self.q.items)
        self.assertEqual(self.q.items[new]['enqueued_ns'],first)
        self.assertEqual(self.q.select(self.roots,1,{'counter'},automatic=True)['candidate_id'],new)
        self.time+=NS; p=self.proposal(sid='9'); p['automatic_eligible']=False
        self.q.offer(p,self.roots,1)
        self.assertIsNone(self.q.select(self.roots,1,{'counter'},automatic=True))
        self.assertEqual(len(self.q.items),1)

    def test_fairness_uses_latest_service_across_collectors(self):
        self.time=1000*NS
        self.q.last={'1:1|counter':10*NS,'1:1|net':700*NS,'2:1|counter':500*NS}
        self.offer('1:1','block'); self.offer('2:1','block')
        self.assertEqual(self.q.select(self.roots,1,{'block'})['target'],'2:1')

    def test_source_routing_never_calls_counter_or_tcp_a_mutex(self):
        for symbol,collector in [('page_counter_try_charge','counter'),('alloc_fd','fd'),('mt_alloc_one','allocator'),
            ('kmem_cache_alloc','allocator'),('release_sock','net'),('skb_release_all','net'),('blk_mq_submit_bio','block'),
            ('mutex_lock','owner'),('rwsem_down_write_slowpath','sync')]:
            report=dict(quality=dict(status='PASS'),session_id='7',survey_epoch=1,window=dict(end_ns=99),
                candidates=[dict(valid=True,target='1:1',top_ip=[dict(symbol=symbol)],rates={})])
            self.assertEqual(recommend(report)[0]['collector'],collector)
