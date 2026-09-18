# SPDX-License-Identifier: GPL-2.0
import json
from pathlib import Path
import unittest
import test_counter_report
import test_collector_manifest
from rwsem_report import reconstruct, analyze
from source_switches import expected_fields


class RwsemReport(unittest.TestCase):
    def row(self,t,phase,actor=1,obj=10,epoch=1,**kwargs):
        return dict(protocol=1,sample_time_ns=t,object=obj,init_ns=epoch,phase=phase,
            actor_id=actor,actor_generation=1 if actor else 0,actor_tid=actor+100,actor_start=1000,
            cpu=0,skipped=0,stack_id=-1,**kwargs)

    def run_rows(self,rows):
        return reconstruct(rows,{(n,1) for n in range(1,20)},{})

    def writer(self):
        return [self.row(1,1),self.row(2,3),self.row(3,5),self.row(4,2,2),
                self.row(10,7),self.row(12,4,2),self.row(15,6,2)]

    def test_writer_reader_and_writer_writer(self):
        for reader in (True,False):
            rows=self.writer()
            if not reader:
                for r in rows:
                    if r['actor_id']==2: r['phase']={2:3,4:5,6:7}[r['phase']]
            o=self.run_rows(rows)[0]; w=o['waits'][1]
            self.assertEqual(w['observed_holders'][0]['holder'],[1,1,101,1000])
            self.assertEqual(w['observed_holders'][0]['interval_ns'],[4,10])
            self.assertEqual(w['observed_holders'][0]['evidence'],'E2')
            self.assertEqual(w['unexplained_elapsed_ns'],2)
            self.assertIsNone(w['spin_cycles']); self.assertFalse(o['reader_set_complete'])

    def test_multi_readers_union_not_sum(self):
        rows=[self.row(1,1),self.row(2,2),self.row(3,4),self.row(4,2,2),self.row(5,4,2),
              self.row(6,3,3),self.row(10,6),self.row(12,6,2),self.row(15,5,3),self.row(18,7,3)]
        w=self.run_rows(rows)[0]['waits'][-1]
        self.assertEqual(len(w['observed_holders']),2); self.assertEqual(w['unexplained_elapsed_ns'],3)

    def test_private_and_readers_do_not_block(self):
        rows=self.writer()
        for r in rows:
            if r['actor_id']==2: r.update(object=20,init_ns=0)
        self.assertFalse(self.run_rows(rows)[1]['waits'][0]['observed_holders'])
        rows=self.writer()
        for r in rows:
            if r['actor_id']==1 and r['phase'] in (3,5,7): r['phase']={3:2,5:4,7:6}[r['phase']]
        self.assertFalse(self.run_rows(rows)[0]['waits'][-1]['observed_holders'])

    def test_address_reuse_requires_observed_new_init(self):
        a=self.writer(); b=[dict(r,sample_time_ns=r['sample_time_ns']+20,init_ns=21) for r in self.writer()]
        self.assertEqual(len(self.run_rows(a+b)),2)
        bad=self.writer(); bad[0]['init_ns']=0
        with self.assertRaises(ValueError): self.run_rows(bad)

    def test_pre_window_and_non_owner_remain_unknown(self):
        rows=[dict(r,init_ns=0) for r in self.writer()[1:]]
        self.assertEqual(self.run_rows(rows)[0]['waits'][1]['observed_holders'][0]['evidence'],'E1')
        rows=self.writer()+[self.row(16,10),self.row(17,11)]
        o=self.run_rows(rows)[0]; self.assertFalse(o['attribution_eligible'])
        self.assertEqual(o['waits'][1]['observed_holders'][0]['evidence'],'E1')

    def test_overflow_does_not_pick_one_reader(self):
        rows=[self.row(1,1)]
        for i in range(1,10): rows.extend([self.row(i*2,2,i),self.row(i*2+1,4,i)])
        rows.append(self.row(30,3,10))
        rows += [self.row(40+i,6,i) for i in range(1,10)]
        rows += [self.row(60,5,10),self.row(70,7,10)]
        o=self.run_rows(rows)[0]; self.assertEqual(o['unknown']['reader_capacity'],1)
        self.assertTrue(all(h['evidence']=='E1' for h in o['waits'][-1]['observed_holders']))

    def test_switch_preemption_abort_and_try_not_spin(self):
        rows=[self.row(1,1),self.row(2,3),self.row(3,5),self.row(4,3,2),
              self.row(8,7),self.row(9,3,3),self.row(10,5,3),self.row(14,7,3),self.row(15,9,2)]
        w=self.run_rows(rows)[0]['waits'][-1]
        self.assertEqual(len(w['observed_holders']),2); self.assertEqual(w['outcome'],'aborted')
        self.assertIsNone(w['spin_cycles'])
        rows=[self.row(1,1),self.row(2,3),self.row(3,5),self.row(4,14,2),self.row(5,16,2),self.row(10,7)]
        w=self.run_rows(rows)[0]['waits'][-1]
        self.assertEqual(w['outcome'],'try_failed'); self.assertFalse(w['observed_holders'])

    def test_downgrade_and_migration_keep_actual_holder(self):
        rows=[self.row(1,1),self.row(2,3),self.row(3,5),self.row(4,12),self.row(5,13),
              self.row(6,3,2),dict(self.row(9,6),actor_id=3),self.row(11,5,2),self.row(12,7,2)]
        w=self.run_rows(rows)[0]['waits'][-1]
        self.assertEqual(w['observed_holders'][0]['holder'][:2],[1,1])
        self.assertEqual(w['observed_holders'][0]['mode'],'read')

    def test_report_quality_and_cap_fail_closed(self):
        r=test_counter_report.CounterReport().record(); r['collector']='rwsem'
        r['inventory']=test_collector_manifest.CollectorContract().inventory('rwsem')
        rows=[dict(session_id='7',kind='RWSEM',id=1,generation=1,detail=' '.join('%s=%s'%v for v in d.items())) for d in self.writer()]
        for kind,detail in [('terminal_counters','received=7 emitted=7 rejected=0'),
            ('terminal_coverage','lost=0 owner_skipped=0'),
            ('terminal_scope','unknown=0 overdepth=0 unmatched=0 nested=0 expired=0 irq_context=0'),
            ('owner_entry_stages','owner_entries=0 sched_entries=0 target_waits=0 watch_events=0')]:
            rows.append(dict(session_id='7',kind=kind,detail=detail))
        run=lambda: analyze(r,'\n'.join(json.dumps(x) for x in rows).encode())
        self.assertEqual(run()['quality']['status'],'PASS')
        rows.append(dict(session_id='7',kind='owner_map_updates',detail='watch_races=0 watch_failed=0 holder_failed=0 attempt_failed=1'))
        self.assertEqual(run()['quality']['status'],'FAIL'); self.assertFalse(run()['objects'])

    def test_source_and_nonowner_api_are_explicit(self):
        root=Path(__file__).resolve().parents[4]
        h=(root/'include/linux/rwsem.h').read_text(); c=(root/'kernel/locking/rwsem.c').read_text()
        self.assertIn('#ifdef CONFIG_CIS_OBSERVE\nextern void down_read_non_owner',h)
        self.assertIn('cis_rwsem_event(sem, CIS_RW_ANONYMOUS_BEGIN)',c)
        self.assertIn('cis_rwsem_event(sem, CIS_RW_INIT)',c)
        self.assertEqual(expected_fields('7','rwsem')['rwsem'],'1')
        with self.assertRaises(ValueError): expected_fields('6','rwsem')


if __name__=='__main__': unittest.main()
