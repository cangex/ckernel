# SPDX-License-Identifier: GPL-2.0
import json
import unittest
from io_pressure_report import analyze_pressure
from source_switches import expected_fields


class Pressure(unittest.TestCase):
    def inputs(self):
        record=dict(window=dict(start_ns=1,end_ns=100),root_identities={
            'a':dict(id=1,generation=1),'b':dict(id=2,generation=1)})
        requests=[dict(request=100,episode_ns=5,selected_container=[2,1],submitter=[2,1,201,3])]
        groups={(100,5):[dict(phase=3,sample_time_ns=20,queue=300,dev_major=8,dev_minor=0)]}
        tags=[dict(queue=300,device=[8,0],container=[1,1],episode_ns=8,tid=101,task_start=3,
                   sleep_intervals=[dict(pool=400,interval_ns=[10,30])])]
        return record,requests,groups,tags

    def shot(self,**changes):
        d=dict(protocol=1,sample_time_ns=20,request=100,episode_ns=5,queue=300,pool=400,
               kind=1,tag=2,depth=8,reserved_tags=1,pool_depth=7,dev_major=8,dev_minor=0)
        d.update(changes)
        return dict(kind='BLOCK_POOL',id=2,generation=1,detail=' '.join('%s=%s'%x for x in d.items()))

    def pause(self,**changes):
        d=dict(protocol=1,begin_ns=12,end_ns=25,tid=101,task_start=3,cgroup_id=90,wb=600,
               bdi=700,bdi_id=8,wb_memcg=90,wb_owner_id=1,wb_owner_generation=1,
               dirty=100,threshold=80,wb_dirty=20,wb_threshold=15,requested_jiffies=5,
               remaining_jiffies=1,cpu=0,stack_id=-1)
        d.update(changes)
        return dict(kind='DIRTY_PAUSE',id=1,generation=1,detail=' '.join('%s=%s'%x for x in d.items()))

    def run_rows(self,rows,inputs=None):
        r,q,g,t=inputs or self.inputs()
        return analyze_pressure(r,'\n'.join(json.dumps(x) for x in rows).encode(),q,g,t)

    def test_waited_pool_association_not_cause(self):
        report,errors=self.run_rows([self.shot(),self.pause()])
        self.assertFalse(errors); self.assertEqual(len(report['wait_pool_associations']),1)
        link=report['wait_pool_associations'][0]
        self.assertEqual(link['snapshot']['submitter'],[2,1,201,3])
        self.assertIsNone(link['blocking_container']); self.assertIsNone(link['exclusive_request_owner'])
        self.assertEqual(report['total_pool_occupancy'],'UNKNOWN')
        self.assertFalse(report['dirty_pauses'][0]['wall_bracket_is_pure_sleep'])

    def test_separate_pool_and_nonoverlap(self):
        report,errors=self.run_rows([self.shot(pool=401)])
        self.assertFalse(errors); self.assertFalse(report['wait_pool_associations'])
        args=self.inputs(); args[3][0]['sleep_intervals'][0]['interval_ns']=[25,30]
        report,errors=self.run_rows([self.shot()],args)
        self.assertFalse(errors); self.assertFalse(report['wait_pool_associations'])

    def test_address_reuse_requires_correct_episode(self):
        for change in (dict(episode_ns=6),dict(queue=301),dict(dev_minor=1),dict(sample_time_ns=21)):
            report,errors=self.run_rows([self.shot(**change)])
            self.assertTrue(errors); self.assertFalse(report['tag_snapshots'])

    def test_depth_change_not_fabricated_occupancy(self):
        report,errors=self.run_rows([self.shot(pool_depth=1)])
        self.assertFalse(errors); self.assertFalse(report['tag_snapshots'][0]['within_current_depth'])
        self.assertFalse(report['wait_pool_associations'])
        for change in (dict(tag=8),dict(reserved_tags=9),dict(pool_depth=9)):
            self.assertTrue(self.run_rows([self.shot(**change)])[1])

    def test_unknown_accounting_owner_and_no_delay_are_preserved(self):
        report,errors=self.run_rows([self.pause(wb_owner_id=0,wb_owner_generation=0,requested_jiffies=0)])
        self.assertFalse(errors); pause=report['dirty_pauses'][0]
        self.assertIsNone(pause['wb_owner']); self.assertFalse(pause['positive_pause_requested'])
        self.assertIsNone(pause['blocking_container'])

    def test_invalid_window_owner_and_duplicate(self):
        for rows in ([self.pause(end_ns=101)],[self.pause(wb_owner_id=3)],[self.shot(),self.shot()],
                     [self.pause(),self.pause()]):
            report,errors=self.run_rows(rows)
            self.assertTrue(errors); self.assertFalse(report['dirty_pauses']); self.assertFalse(report['tag_snapshots'])

    def test_source_off_contract(self):
        self.assertEqual(expected_fields('18','block')['wb_pause'],'1')
        self.assertEqual(expected_fields('18',None)['wb_pause'],'0')
