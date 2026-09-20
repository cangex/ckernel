# SPDX-License-Identifier: GPL-2.0
import json
from pathlib import Path
import unittest

from page_backend_report import analyze
from collector_manifest import contract
from periodic_plan import digest
from source_switches import expected_fields
import test_collector_manifest
import test_prototype


class PageBackend(unittest.TestCase):
    def record(self):
        r=test_prototype.Explanations().record()
        r.update(collector='page_backend',backend_selection=dict(cache='page_zone',nodes=[0]),
                 collector_contract_sha256=digest(contract('page_backend')),
                 inventory=test_collector_manifest.CollectorContract().inventory('page_backend'))
        r['receipt']['producer_recursion']=dict(required=True,valid=True,skipped=0)
        return r

    def event(self,actor=1,zone=100,begin=10,**updates):
        d=dict(protocol=1,begin_ns=begin,acquired_ns=begin+1,releasing_ns=begin+2,end_ns=begin+3,
               tid=actor+100,task_start=1,cgroup_id=actor,cpu=0,zone=zone,node=0,zone_index=2,order=0,
               operation=1,sample_shift=6,requested_pages=32,completed_pages=30,stack_id=-1)
        d.update(updates)
        return dict(kind='PAGE_BACKEND',id=actor,generation=1,detail=' '.join('%s=%s'%v for v in d.items()))

    def run_rows(self,rows,record=None):
        tail=[('backend_source_filter','protocol=1 lease=1 readback=1 cache=page_zone nodes=0 node_scope=page_zone allocation_release_scope=not_tracked'),
              ('backend_source_filter_closed','lease=0 close_after_detach=1'),
              ('terminal_counters','received=2 emitted=2 rejected=0'),
              ('terminal_coverage','lost=0 owner_skipped=0'),
              ('terminal_scope','unknown=0 overdepth=0 unmatched=0 nested=0 expired=0 irq_context=0'),
              ('owner_entry_stages','owner_entries=0 sched_entries=0 target_waits=0 watch_events=0')]
        rows=rows+[dict(kind=k,detail=v) for k,v in tail]
        raw='\n'.join(json.dumps(dict(row,session_id='7')) for row in rows).encode()
        return analyze(record or self.record(),raw)

    def test_shared_backend_not_holder(self):
        r=self.run_rows([self.event(),self.event(actor=2,begin=30)])
        self.assertEqual(r['quality']['status'],'PASS')
        self.assertEqual(len(r['shared_backends']),1)
        self.assertEqual(r['shared_backends'][0]['evidence'],'E1')
        for e in r['episodes']:
            self.assertIsNone(e['holder']); self.assertIsNone(e['blocking_container'])
            self.assertEqual(e['wait_to_acquire_wall_ns'],1)
            self.assertEqual(e['held_inner_wall_ns'],1)

    def test_private_zones_unknown_actors_and_window(self):
        r=self.run_rows([self.event(),self.event(actor=2,zone=200,begin=30)])
        self.assertFalse(r['shared_backends'])
        for e in (self.event(actor=3),self.event(begin=99),self.event(node=1)):
            r=self.run_rows([e]); self.assertNotEqual(r['quality']['status'],'PASS')
            self.assertFalse(r['shared_backends'])

    def test_malformed_partial_and_duplicate(self):
        for rows in ([self.event(acquired_ns=99)], [self.event(completed_pages=33)],
                     [self.event(order=-1)], [self.event(),self.event()]):
            r=self.run_rows(rows); self.assertNotEqual(r['quality']['status'],'PASS')
            self.assertTrue(all(e['evidence']=='UNACCEPTED' for e in r['episodes']))
        r=self.record(); r['result']='PARTIAL'
        self.assertFalse(self.run_rows([self.event(),self.event(actor=2)],r)['shared_backends'])

    def test_failed_allocation_and_mixed_order_drain(self):
        r=self.run_rows([self.event(operation=3,requested_pages=1,completed_pages=0),
                         self.event(actor=2,begin=30,operation=2,order=-1,completed_pages=36)])
        self.assertEqual(r['quality']['status'],'PASS')
        self.assertEqual([e['operation'] for e in r['episodes']],['buddy_allocate','pcp_drain'])

    def test_no_callback_inside_zone_critical_section(self):
        root=Path(__file__).resolve().parents[4]
        code=(root/'include/linux/cis_page_backend.h').read_text()
        for name,next_name in [('cis_page_acquired','cis_page_releasing'),('cis_page_releasing','cis_page_end')]:
            body=code.split('static inline void '+name,1)[1].split('static inline void '+next_name,1)[0]
            self.assertNotIn('trace_',body)
            self.assertIn('ktime_get_ns',body)
        page=(root/'mm/page_alloc.c').read_text()
        for marker in ('CIS_PB_REFILL','CIS_PB_DRAIN','CIS_PB_ALLOC','CIS_PB_FREE'): self.assertIn(marker,page)
        self.assertEqual(expected_fields('16','page_backend')['page_backend'],'1')
        self.assertEqual(expected_fields('16',None)['backend_filter'],'0')
        with self.assertRaises(ValueError): expected_fields('15','page_backend')
