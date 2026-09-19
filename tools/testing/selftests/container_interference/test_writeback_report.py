# SPDX-License-Identifier: GPL-2.0
import json
import unittest

from writeback_report import analyze_writeback
from source_switches import expected_fields


class WritebackReport(unittest.TestCase):
    def row(self, time, phase, **changes):
        d=dict(protocol=1,sample_time_ns=time,episode_ns=10,phase=phase,inode=100,ino=20,
            inode_generation=5,dev_major=8,dev_minor=0,folio_index=0,tid=42,task_start=1,
            actor_id=0,actor_generation=0,wbc=200,memcg=7,wb_owner_id=1,wb_owner_generation=1,
            request=300 if phase==4 else 0,request_episode=time if phase==4 else 0)
        d.update(changes)
        return dict(kind='WRITEBACK',id=1,generation=1,detail=' '.join('%s=%s'%p for p in d.items()))

    def analyze(self, rows, requests=None):
        record=dict(window=dict(start_ns=1,end_ns=100),root_identities={'a':dict(id=1,generation=1)},
            inventory=dict(program_names=['wb_dirty','wb_begin','wb_end']))
        requests=requests if requests is not None else [dict(request=300,episode_ns=20,submitter=[0,0,42,1])]
        return analyze_writeback(record,'\n'.join(json.dumps(r) for r in rows).encode(),requests)

    def test_real_context_not_unique_dirtier_or_bio_owner(self):
        report,bad=self.analyze([self.row(10,2),self.row(20,4),self.row(30,3)])
        self.assertFalse(bad); self.assertEqual(len(report['request_links']),1)
        context=report['request_links'][0]['context']
        self.assertEqual(context['executor'],[0,0,42,1]); self.assertEqual(context['wb_owner'],[1,1])
        self.assertIsNone(context['exclusive_dirtier']); self.assertIsNone(context['blocking_container'])

    def test_private_inode_does_not_link_another_request_or_actor(self):
        rows=[self.row(10,2),self.row(20,4),self.row(30,3)]
        report,bad=self.analyze(rows,[])
        self.assertFalse(bad); self.assertFalse(report['request_links'])
        report,bad=self.analyze(rows,[dict(request=300,episode_ns=20,submitter=[1,1,42,1])])
        self.assertIn('writeback_request_context_conflict',bad); self.assertFalse(report['request_links'])

    def test_missing_boundaries_and_window_reject_inference(self):
        for rows in ([self.row(20,4),self.row(30,3)],[self.row(10,2),self.row(20,4)]):
            report,bad=self.analyze(rows); self.assertFalse(bad); self.assertFalse(report['request_links'])
        report,bad=self.analyze([self.row(10,2),self.row(20,4),self.row(101,3)])
        self.assertIn('writeback_outside_window',bad); self.assertFalse(report['request_links'])

    def test_inode_address_reuse_or_wbc_change_cannot_stitch(self):
        for change in (dict(inode=101),dict(ino=21),dict(inode_generation=6),dict(wbc=201),dict(memcg=8)):
            report,bad=self.analyze([self.row(10,2),self.row(20,4,**change),self.row(30,3)])
            self.assertIn('writeback_context_changed',bad); self.assertFalse(report['request_links'])

    def test_duplicate_nested_and_late_events_invalidate(self):
        for extra in ([self.row(20,4)], [self.row(25,3)], [self.row(40,4)]):
            report,bad=self.analyze([self.row(10,2),self.row(20,4),self.row(30,3)]+extra)
            if bad: self.assertFalse(report['request_links'])
            else: self.assertFalse(report['request_links'])
        rows=[self.row(10,2),self.row(20,4),self.row(30,3),
              self.row(15,2,episode_ns=15,wbc=201),self.row(25,3,episode_ns=15,wbc=201)]
        report,bad=self.analyze(rows); self.assertIn('writeback_overlapping_task_contexts',bad)

    def test_dirty_observation_does_not_become_owner_through_address_match(self):
        dirty=self.row(5,1,episode_ns=5,actor_id=1,actor_generation=1,wbc=0,memcg=0,
            wb_owner_id=0,wb_owner_generation=0)
        report,bad=self.analyze([dirty,self.row(10,2),self.row(20,4),self.row(30,3)])
        self.assertFalse(bad); self.assertEqual(len(report['dirty_observations']),1)
        self.assertFalse(report['dirty_observations'][0]['all_writes_covered'])
        self.assertIsNone(report['contexts'][0]['exclusive_dirtier'])

    def test_early_worker_zero_epoch_closed_context_only(self):
        report,bad=self.analyze([self.row(10,2,task_start=0),self.row(20,4,task_start=0),
            self.row(30,3,task_start=0)],[dict(request=300,episode_ns=20,submitter=[0,0,42,0])])
        self.assertFalse(bad); self.assertEqual(len(report['request_links']),1)

    def test_switch_inventory(self):
        for collector,value in (('block','1'),(None,'0'),('net','0')):
            actual=expected_fields('12',collector)
            for key in ('wb_dirty','wb_begin','wb_end'): self.assertEqual(actual[key],value)
