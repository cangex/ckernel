# SPDX-License-Identifier: GPL-2.0
import copy
import unittest

from block_tag_report import tag_episodes
from collector_manifest import contract, validate_inventory, validate_record_inventory
from periodic_plan import digest
from source_switches import expected_fields
import test_block_report


class TagReport(unittest.TestCase):
    def row(self, time, phase, **changes):
        data = dict(protocol=1, sample_time_ns=time, episode_ns=10, tid=101,
                    task_start=1, queue=2000, pool=3000, phase=phase, alloc_flags=0,
                    tag=2 if phase==4 else -1, dev_major=8, dev_minor=0,
                    actor_id=1, actor_generation=1, cpu=0, stack_id=-17)
        data.update(changes)
        return dict(session_id='7', kind='BLOCK_TAG', id=1, generation=1,
                    detail=' '.join('%s=%s' % x for x in data.items()))

    def run_rows(self, rows):
        return test_block_report.BlockReport().run_rows(rows)

    def test_sleep_is_distinct_from_whole_slow_call(self):
        report = self.run_rows([self.row(t,p) for t,p in ((10,1),(20,2),(40,3),(50,4))])
        self.assertEqual(report['quality']['status'],'PASS',report)
        tag = report['tag_waits'][0]
        self.assertEqual(tag['interval_ns'],[10,50])
        self.assertEqual(tag['sleep_intervals'][0]['interval_ns'],[20,40])
        self.assertEqual(tag['outcome'],'TAG_FOUND')
        self.assertIsNone(tag['blocking_container'])
        self.assertEqual(tag['request_allocation_success'],'NOT_ESTABLISHED')

    def test_nowait_is_not_a_sleep(self):
        tag = self.run_rows([self.row(10,5,alloc_flags=1)])['tag_waits'][0]
        self.assertEqual(tag['outcome'],'NOWAIT_REJECTED')
        self.assertEqual(tag['sleep_intervals'],[])

    def test_retry_without_sleep_and_truncated_window(self):
        for rows,outcome,unfinished in (([self.row(10,1),self.row(20,4)],'TAG_FOUND',False),
                                       ([self.row(10,1),self.row(20,2)],'UNOBSERVED',True)):
            tag=self.run_rows(rows)['tag_waits'][0]
            self.assertEqual(tag['outcome'],outcome)
            self.assertEqual(tag['unfinished_sleep'],unfinished)
            if unfinished: self.assertIsNone(tag['interval_ns'][1])

    def test_migration_can_change_pool_after_wakeup_not_during_sleep(self):
        rows=[self.row(10,1),self.row(20,2),self.row(30,3,cpu=1),
              self.row(40,2,cpu=1,pool=4000),self.row(50,3,cpu=1,pool=4000),
              self.row(60,4,cpu=1,pool=4000)]
        report=self.run_rows(rows)
        self.assertEqual(report['quality']['status'],'PASS',report)
        self.assertTrue(report['tag_waits'][0]['pool_changed'])
        bad=copy.deepcopy(rows); bad[2]=self.row(30,3,pool=4000)
        self.assertEqual(self.run_rows(bad)['quality']['status'],'FAIL')

    def test_bad_pairs_reuse_or_owner_do_not_make_relations(self):
        for rows in ([self.row(20,2),self.row(30,3)],
                     [self.row(10,1),self.row(20,3)],
                     [self.row(10,1),self.row(20,2),self.row(30,4)],
                     [self.row(10,1),self.row(20,4),self.row(30,4)],
                     [self.row(10,1),self.row(20,4,queue=9000)],
                     [self.row(10,1),self.row(20,4,actor_id=999)]):
            report=self.run_rows(rows)
            self.assertEqual(report['quality']['status'],'FAIL',report)
            self.assertEqual(report['tag_waits'],[])

    def test_two_containers_same_pool_are_not_a_holder_edge(self):
        rows=[self.row(10,1),self.row(20,2),self.row(40,3),self.row(50,4)]
        for t,p in ((15,1),(25,2),(45,3),(55,4)):
            r=self.row(t,p,episode_ns=15,tid=102,actor_id=2)
            r['id']=2; rows.append(r)
        report=self.run_rows(rows)
        self.assertEqual(len(report['tag_waits']),2,report)
        self.assertTrue(all(x['blocking_container'] is None for x in report['tag_waits']))

    def test_historical_block_contract_is_read_only(self):
        record=test_block_report.BlockReport().record(); old=contract('block',legacy_block=True)
        inv=record['inventory']
        for field in ('program','map'):
            inv[field+'_names']=old[field+'s']
            inv[field+'s']=list(range(1,1+len(old[field+'s'])))
        record['collector_contract_sha256']=digest(old)
        self.assertEqual(validate_record_inventory(record),digest(old))
        with self.assertRaises(ValueError): validate_inventory('block',inv)
        record['collector_contract_sha256']='unknown'
        with self.assertRaises(ValueError): validate_record_inventory(record)

    def test_source_switch_requires_tag_only_in_new_version(self):
        self.assertNotIn('block_tag',expected_fields('8','block'))
        self.assertEqual(expected_fields('9','block')['block_tag'],'1')
        self.assertEqual(expected_fields('9',None)['block_tag'],'0')

    def test_nowait_flags_and_initial_actor_must_match(self):
        for rows in ([self.row(10,5,alloc_flags=0)],
                     [self.row(10,1,alloc_flags=1),self.row(20,4,alloc_flags=1)],
                     [self.row(10,1,actor_id=2),self.row(20,4)]):
            self.assertEqual(self.run_rows(rows)['quality']['status'],'FAIL')

    def test_later_cgroup_change_is_not_reassigned_to_new_container(self):
        report=self.run_rows([self.row(10,1),self.row(20,2),
                              self.row(30,3,actor_id=2),self.row(40,4,actor_id=2)])
        self.assertEqual(report['quality']['status'],'PASS',report)
        tag=report['tag_waits'][0]
        self.assertEqual(tag['container'],[1,1])
        self.assertEqual(len(tag['identity_changes']),2)
        self.assertIsNone(tag['blocking_container'])

    def test_task_reuse_does_not_join_overlapping_lifetimes(self):
        first=[self.row(10,1),self.row(40,4)]
        overlap=[self.row(20,1,episode_ns=20),self.row(50,4,episode_ns=20)]
        self.assertEqual(self.run_rows(first+overlap)['quality']['status'],'FAIL')
        other=[self.row(20,1,episode_ns=20,task_start=2),self.row(50,4,episode_ns=20,task_start=2)]
        self.assertEqual(self.run_rows(first+other)['quality']['status'],'FAIL')
        reused=[self.row(50,1,episode_ns=50,task_start=2),self.row(60,4,episode_ns=50,task_start=2)]
        result=self.run_rows(first+reused)
        self.assertEqual(result['quality']['status'],'PASS',result)
        self.assertEqual(len(result['tag_waits']),2)
