# SPDX-License-Identifier: GPL-2.0
import json
import unittest
import test_counter_report
import test_collector_manifest
from net_report import analyze


class NetReport(unittest.TestCase):
    def record(self):
        r=test_counter_report.CounterReport().record(); r['collector']='net'
        r['inventory']=test_collector_manifest.CollectorContract().inventory('net')
        return r

    def row(self,time,phase,who=1,cookie=100,sock=1000,skb=0,queue=0,context=0,**changes):
        d=dict(protocol=1,sample_time_ns=time,phase=phase,context=context,cookie=cookie,socket=sock,
            skb=skb,queue_ns=queue,actor_id=who if not context else 0,actor_generation=1 if who and not context else 0,
            actor_tid=who+100 if not context else 0,actor_start=1 if not context else 0,
            cpu=0,netns=100,bytes=128 if skb else 0,backlog_bytes=0,packet_flags=0,stack_id=-1)
        d.update(changes)
        return dict(session_id='7',kind='NET',id=1,generation=1,detail=' '.join('%s=%s'%p for p in d.items()))

    def run_rows(self,rows,record=None):
        rows=list(rows)
        for kind,detail in (
            ('terminal_counters','received=20 emitted=20 rejected=0'),
            ('terminal_coverage','lost=0 owner_skipped=0'),
            ('terminal_scope','unknown=0 overdepth=0 unmatched=0 nested=0 expired=0 irq_context=0'),
            ('owner_entry_stages','owner_entries=0 sched_entries=0 target_waits=0 watch_events=0')):
            rows.append(dict(session_id='7',kind=kind,detail=detail))
        return analyze(record or self.record(),'\n'.join(json.dumps(r) for r in rows).encode())

    def test_shared_logical_owner_not_spin_cycles(self):
        r=self.run_rows([self.row(10,2),self.row(20,1,who=2),self.row(30,3),self.row(40,2,who=2),self.row(50,3,who=2)])
        self.assertEqual(r['quality']['status'],'PASS',r)
        wait=r['sockets'][0]['waits'][0]
        self.assertEqual(wait['observed_holders'][0]['holder'],[1,1,101,1])
        self.assertEqual(wait['observed_holders'][0]['interval_ns'],[20,30])
        self.assertEqual(wait['observed_holders'][0]['relation_scope'],'cross_container')
        self.assertEqual(wait['unexplained_wait_ns'],10)
        self.assertIsNone(wait['spin_cycles'])

    def test_creator_is_not_transferred_user_or_changing_holder(self):
        r=self.run_rows([self.row(10,10),self.row(20,2,who=2),self.row(30,3,who=2)])
        self.assertEqual(r['quality']['status'],'PASS',r)
        sock=r['sockets'][0]
        self.assertEqual(sock['creation_owner'],[1,1,101,1])
        self.assertEqual(sock['creation_observation']['time_ns'],10)
        self.assertIsNone(sock['accept_observation'])
        self.assertFalse(sock['backlog'])
        self.assertEqual(sock['observed_actors'],[[1,1,101,1],[2,1,102,1]])

    def test_passive_child_accept_is_not_creation(self):
        r=self.run_rows([self.row(10,11),self.row(20,2,who=2),self.row(30,3,who=2)])
        sock=r['sockets'][0]
        self.assertEqual(sock['creation_owner'],'UNOBSERVED')
        self.assertIsNone(sock['creation_observation'])
        self.assertEqual(sock['accept_observation']['actor'],[1,1,101,1])

    def test_pre_window_and_address_reuse_never_supply_creator(self):
        r=self.run_rows([self.row(10,10),self.row(20,2,who=2,cookie=200),self.row(30,3,who=2,cookie=200)])
        self.assertEqual(r['sockets'][0]['creation_owner'],[1,1,101,1])
        self.assertEqual(r['sockets'][1]['creation_owner'],'UNOBSERVED')

    def test_invalid_duplicate_or_irq_provenance_fails_closed(self):
        for rows in ([self.row(10,10),self.row(20,10)],
                     [self.row(10,10),self.row(20,11)],
                     [self.row(10,11,context=1)],
                     [self.row(10,10,skb=9)],
                     [self.row(10,11,queue=1)]):
            r=self.run_rows(rows)
            self.assertEqual(r['quality']['status'],'FAIL',r)
            self.assertFalse(r['sockets'])

    def test_private_and_reused_address_do_not_join(self):
        rows=[self.row(10,2),self.row(30,3),self.row(20,1,who=2,cookie=200),self.row(40,2,who=2,cookie=200),self.row(50,3,who=2,cookie=200)]
        r=self.run_rows(rows)
        self.assertFalse(r['sockets'][1]['waits'][0]['observed_holders'])
        self.assertEqual(len(r['sockets']),2)

    def test_holder_switch_and_preempted_gap_not_exclusive_cause(self):
        r=self.run_rows([self.row(10,2),self.row(20,1,who=2),self.row(30,3),
            self.row(35,2),self.row(45,3),self.row(50,2,who=2),self.row(60,3,who=2)])
        wait=r['sockets'][0]['waits'][0]
        self.assertEqual(len(wait['observed_holders']),2)
        self.assertEqual(wait['unexplained_wait_ns'],10)
        self.assertEqual(wait['causal'],'NOT_ESTABLISHED')

    def test_window_before_holder_unknown_and_fast_pair(self):
        r=self.run_rows([self.row(10,1,who=2),self.row(20,3),self.row(30,2,who=2),self.row(40,3,who=2),self.row(50,4),self.row(60,5)])
        self.assertFalse(r['sockets'][0]['waits'][0]['observed_holders'])
        self.assertEqual(r['sockets'][0]['owner_unknown']['unobserved_acquire'],1)

    def test_release_during_callback_and_reused_skb_are_separate(self):
        rows=[self.row(10,2),self.row(20,6,context=1,skb=9,queue=20),
              self.row(30,7,skb=9,queue=20),self.row(35,9,context=1,skb=9,queue=20),
              self.row(36,6,context=1,skb=9,queue=36),self.row(40,8,skb=9,queue=20),
              self.row(45,7,skb=9,queue=36),self.row(46,9,skb=9,queue=36),self.row(48,8,skb=9,queue=36),self.row(60,3)]
        r=self.run_rows(rows); self.assertEqual(r['quality']['status'],'PASS',r)
        a,b=r['sockets'][0]['backlog']
        self.assertEqual(a['residence_ns'],10); self.assertEqual(b['residence_ns'],9)
        self.assertIsNone(a['queue_executor']); self.assertIsNone(a['release_executor'])
        self.assertEqual(a['packet_origin'],'UNKNOWN')
        self.assertEqual(a['release_context'],'softirq')

    def test_forged_irq_actor_and_duplicate_release_fail_closed(self):
        for rows in ([self.row(10,6,skb=9,queue=10,context=1,actor_id=1)],
                     [self.row(10,2),self.row(20,2,who=2)],
                     [self.row(10,2),self.row(20,3,who=2)],
                     [self.row(10,2),self.row(20,3,sock=2000)]):
            r=self.run_rows(rows); self.assertEqual(r['quality']['status'],'FAIL'); self.assertFalse(r['sockets'])

    def test_missing_service_and_packet_transform_remain_unknown(self):
        r=self.run_rows([self.row(10,6,skb=9,queue=10,context=1,packet_flags=7),self.row(20,9,skb=9,queue=10,packet_flags=7)])
        q=r['sockets'][0]['backlog'][0]
        self.assertIsNone(q['residence_ns']); self.assertEqual(q['packet_flags'],7)
        self.assertEqual(q['data_buffer_owner'],'UNKNOWN'); self.assertIsNone(q['blocking_container'])

    def test_loss_and_partial_producer_reject_relations(self):
        r=self.record(); r['receipt']['producer_recursion']['skipped']=1
        result=self.run_rows([self.row(10,2),self.row(20,3)],r)
        self.assertFalse(result['sockets']); self.assertEqual(result['quality']['status'],'FAIL')
