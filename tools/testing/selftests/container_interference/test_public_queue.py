# SPDX-License-Identifier: GPL-2.0
import json
import unittest
from collector_manifest import contract
from periodic_plan import digest
from queue_report import analyze
from session import validate, worker_roots
from source_switches import expected_fields
import resource_policy
import test_collector_manifest
import test_prototype


class PublicQueue(unittest.TestCase):
    def record(self):
        r=test_prototype.Explanations().record()
        r.update(collector='qdisc',queue_selection=dict(ifindex=5,tx_queue=0),
                 collector_contract_sha256=digest(contract('qdisc')),
                 inventory=test_collector_manifest.CollectorContract().inventory('qdisc'))
        r['receipt']['producer_recursion']=dict(required=True,valid=True,skipped=0)
        return r

    def event(self,actor=1,begin=10,**updates):
        d=dict(protocol=1,begin_ns=begin,acquired_ns=begin+1,end_ns=begin+2,lease=7,
            qdisc=100,txq=200,dev=300,skb=400,actor_cgroup=actor,socket_cgroup=actor,
            txq_state=0,netns=77,ifindex=5,queue=0,handle=65536,operation=1,sample_shift=4,
            qlen_begin=1,qlen_end=2,backlog_begin=1000,backlog_end=2000,length=1000,
            context=0,flags=0,packets=1,result=0,actor_id=actor,actor_generation=1,
            socket_id=actor,socket_generation=1,tid=100+actor,task_start=1,cpu=0)
        d.update(updates)
        return dict(kind='QDISC',id=0,generation=0,detail=' '.join('%s=%s'%x for x in d.items()))

    def run_rows(self,rows,record=None,terminal='valid=1 unchanged=1'):
        tail=[('queue_source_filter','protocol=1 lease=7 valid=1 netns=77 ifindex=5 queue=0 handle=65536 qdisc=100 pinned=1 readback=1'),
              ('queue_source_filter_closed','lease=0 close_after_detach=1'),
              ('queue_source_terminal',terminal),
              ('queue_native_audit','valid=1 entries=6 filtered=1 sampled=4 emitted=4 expired=0 recursive=0 endpoint_snapshot=1 unfinished_unknown=1'),
              ('terminal_counters','received=2 emitted=2 rejected=0'),
              ('terminal_coverage','lost=0 owner_skipped=0'),
              ('terminal_scope','unknown=0 overdepth=0 unmatched=0 nested=0 expired=0 irq_context=0'),
              ('owner_entry_stages','owner_entries=0 sched_entries=0 target_waits=0 watch_events=0')]
        rows=rows+[dict(kind=k,detail=v) for k,v in tail]
        return analyze(record or self.record(),'\n'.join(json.dumps(dict(row,session_id='7')) for row in rows).encode())

    def test_queue_sharing_not_a_holder_or_cause(self):
        r=self.run_rows([self.event(),self.event(actor=2,begin=30)])
        self.assertEqual(r['quality']['status'],'PASS')
        self.assertEqual(len(r['shared_resources']),2)
        self.assertEqual(r['coverage']['backlog_samples'],2)
        for sample in r['samples']:
            self.assertIsNone(sample['holder']); self.assertIsNone(sample['blocking_container'])
            self.assertIsNone(sample['packet_owner']); self.assertFalse(sample['wire_completion'])

    def test_unknown_irq_and_forwarding_preserved(self):
        r=self.run_rows([self.event(actor=0,actor_generation=0,socket_generation=0,tid=0,
                                  task_start=0,context=1,operation=2,acquired_ns=0)])
        self.assertEqual(r['quality']['status'],'PASS')
        self.assertEqual(r['coverage']['unknown_executors'],1)
        self.assertEqual(r['coverage']['unknown_socket_accounting'],1)
        self.assertFalse(r['shared_resources'])

    def test_executor_billing_not_merged_into_owner(self):
        r=self.run_rows([self.event(socket_id=2,socket_cgroup=2),self.event(actor=2,begin=30)])
        self.assertEqual(r['quality']['status'],'PASS')
        self.assertEqual([s['role'] for s in r['shared_resources']],['executor'])

    def test_private_queue_one_actor_no_sharing(self):
        r=self.run_rows([self.event(qlen_begin=0,qlen_end=0,backlog_begin=0,backlog_end=0)])
        self.assertEqual(r['coverage']['backlog_samples'],0); self.assertFalse(r['shared_resources'])

    def test_wrong_resource_epoch_and_window_rejected(self):
        for e in (self.event(lease=8),self.event(ifindex=6),self.event(qdisc=101),self.event(netns=78),
                  self.event(begin=99),self.event(actor=3),self.event(context=1),self.event(sample_shift=0)):
            r=self.run_rows([self.event(actor=2,begin=30),e])
            self.assertEqual(r['quality']['status'],'FAIL'); self.assertFalse(r['shared_resources'])

    def test_mutation_duplicate_and_unknown_cannot_pass(self):
        self.assertEqual(self.run_rows([self.event()],terminal='valid=0 unchanged=0')['quality']['status'],'FAIL')
        self.assertEqual(self.run_rows([self.event(),self.event()])['quality']['status'],'FAIL')
        self.assertEqual(self.run_rows([self.event(),self.event(actor=2,begin=30,txq=201)])['quality']['status'],'FAIL')
        r=self.record(); r['result']='PARTIAL'
        self.assertFalse(self.run_rows([self.event(),self.event(actor=2,begin=30)],r)['shared_resources'])
        self.assertEqual(self.run_rows([])['coverage']['observation_status'],'NO_ACCEPTED_SAMPLES')

    def test_explicit_queue_and_identity_universe(self):
        req=dict(version=1,op='start',collector='qdisc',targets=['1'],nonce='qtest',queue=dict(ifindex=5,tx_queue=0))
        validate(req)
        for q in (None,{},dict(ifindex=0,tx_queue=0),dict(ifindex=True,tx_queue=0),
                  dict(ifindex=5,tx_queue=-1),dict(ifindex=5,tx_queue=2**31),dict(ifindex=5,tx_queue=0,x=1)):
            with self.assertRaises(ValueError): validate(dict(req,queue=q))
        with self.assertRaises(ValueError): validate(dict(req,collector='ip'))
        self.assertEqual(set(worker_roots({'1':{},'2':{}},['1'],'qdisc')),{'1','2'})
        self.assertEqual(expected_fields('19','qdisc')['qdisc'],'1')
        with self.assertRaises(ValueError): expected_fields('18','qdisc')
        resource_policy.admit(resource_policy.policy(),'qdisc')
        with self.assertRaises(PermissionError): resource_policy.admit(resource_policy.policy(),'qdisc',automatic=True)

    def test_no_per_packet_map_or_private_socket_source(self):
        c=contract('qdisc')
        self.assertEqual(c['programs'],['qdisc_state'])
        self.assertEqual(set(c['maps']),{'session_window','roots','events','stats','targets'})
