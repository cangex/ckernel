# SPDX-License-Identifier: GPL-2.0
import unittest
from y2_memory_check import counter_ownership, audit_totals


class Y2Memory(unittest.TestCase):
    def rows(self,parents):
        roots=[dict(cgroup_id=10+i,parent_id=v) for i,v in enumerate(parents)]
        actors=[(1,1),(2,1)]
        calls=[dict(actor=[*a,100+i,1],operation='charge',steps=[dict(owner_cgroup=v,resource_kind='memory')
            for v in (roots[i]['cgroup_id'],parents[i],4)]) for i,a in enumerate(actors)]
        return dict(calls=calls),actors,roots,4

    def test_common_and_private_ancestors(self):
        for parents in ([5,5],[5,6]):
            self.assertEqual(counter_ownership(*self.rows(parents))['status'],'PASS')

    def test_private_parent_misattribution_fails(self):
        report,*rest=self.rows([5,6]); report['calls'][1]['steps'].append(dict(owner_cgroup=5,resource_kind='memory'))
        self.assertIn('private_parent_cross_attribution',counter_ownership(report,*rest)['errors'])

    def test_missing_owner_cannot_be_filled_from_actor(self):
        report,*rest=self.rows([5,5]); report['calls'][0]['steps'][0]['owner_cgroup']=0
        self.assertNotEqual(counter_ownership(report,*rest)['status'],'PASS')

    def test_source_off_counters(self):
        self.assertEqual(audit_totals('version=1 bytes_per_cpu=64\ncpu=0 entries=4 callback_ns=8 callback_max_ns=6\ncpu=1 entries=2 callback_ns=3 callback_max_ns=3'),
                         dict(entries=6,callback_ns=11))
