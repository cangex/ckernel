# SPDX-License-Identifier: GPL-2.0
import unittest
from copy import deepcopy

import test_block_report
import test_collector_manifest
from collector_manifest import contract
from periodic_plan import digest


class MergeReport(unittest.TestCase):
    def setUp(self): self.h = test_block_report.BlockReport()

    def record(self):
        r = self.h.record()
        r['inventory'] = test_collector_manifest.CollectorContract().inventory('block')
        r['collector_contract_sha256'] = digest(contract('block'))
        return r

    def meta(self, kind, time, **changes):
        d = dict(protocol=1, sample_time_ns=time, request=1000, episode_ns=10, bio=3000)
        if kind == 'BLOCK_LINK':
            d.update(queue=2000, victim=0, victim_episode_ns=0, merge_kind=2, before_bytes=4096, added_bytes=4096)
        else:
            d.update(index=0, bytes=4096, remaining=4096, more=0, bio_cgroup=1,
                     bio_owner_id=1, bio_owner_generation=1, bio_origin_overdepth=0)
        d.update(changes)
        return dict(session_id='7', kind=kind, id=1, generation=1, detail=' '.join('%s=%s' % v for v in d.items()))

    def appended(self):
        return [self.h.row(10,1), self.meta('BLOCK_LINK',20,bio=3001),
            self.h.row(30,3,remaining=8192,multi_bio=1),
            self.meta('BLOCK_BIO',30,remaining=8192,more=1),
            self.meta('BLOCK_BIO',30,remaining=8192,index=1,bio=3001),
            self.h.row(40,5,remaining=8192,completed=8192,multi_bio=1)]

    def check(self, rows, status='PASS'):
        r = self.h.run_rows(rows,self.record()); self.assertEqual(r['quality']['status'],status,r)
        if status == 'FAIL':
            self.assertFalse(r['requests']); self.assertFalse(r['provenance']['merge_transfers'])
        return r

    def test_bio_append_weights_not_blocker(self):
        p=self.check(self.appended())['provenance']
        self.assertEqual(p['merge_transfers'][0]['state'],'BIO_APPEND')
        s=p['issue_sources'][0]
        self.assertEqual(s['sources'],[dict(container=[1,1],bytes=8192,fraction=1.0)])
        self.assertIsNone(s['blocking_container'])

    def test_observed_request_transfer(self):
        rows=self.appended()
        rows.insert(1,self.h.row(15,1,request=1001,epoch=15,bio=3001))
        rows[2]=self.meta('BLOCK_LINK',20,bio=3001,merge_kind=1,victim=1001,victim_episode_ns=15)
        rows.insert(3,self.h.row(21,6,request=1001,epoch=15,bio=3001))
        p=self.check(rows)['provenance']
        self.assertEqual(p['merge_transfers'][0]['state'],'OBSERVED_TRANSFER')
        self.assertEqual(p['merge_transfers'][0]['victim'],[1001,15])

    def test_unwatched_victim_is_unknown_not_invented_owner(self):
        rows=self.appended(); rows[1]=self.meta('BLOCK_LINK',20,bio=3001,merge_kind=1,victim=1001)
        p=self.check(rows)['provenance']
        self.assertEqual(p['merge_transfers'][0]['state'],'UNOBSERVED_VICTIM_EPISODE')

    def test_missing_merge_or_snapshot_or_duplicate_rejected(self):
        for index in (1,3,4):
            rows=self.appended(); rows.pop(index); self.check(rows,'FAIL')
        rows=self.appended(); rows.append(deepcopy(rows[3])); self.check(rows,'FAIL')

    def test_false_survivor_victim_epoch_and_malformed_bounds(self):
        for changes in (dict(victim=1000,merge_kind=1),dict(victim=1001,merge_kind=1,victim_episode_ns=12),
                        dict(before_bytes=2048),dict(added_bytes=8192),dict(queue=9999),dict(merge_kind=9)):
            rows=self.appended(); rows[1]=self.meta('BLOCK_LINK',20,**changes); self.check(rows,'FAIL')

    def test_unregistered_origin_is_unknown_not_current(self):
        rows=self.appended()
        rows[4]=self.meta('BLOCK_BIO',30,remaining=8192,index=1,bio=3001,bio_cgroup=999,
                          bio_owner_id=0,bio_owner_generation=0)
        s=self.check(rows)['provenance']['issue_sources'][0]
        self.assertEqual(s['unknown_bytes'],4096); self.assertEqual(s['sources'][0]['fraction'],.5)

    def test_snapshot_cap_keeps_unknown_remainder(self):
        size=9*4096
        rows=[self.h.row(10,1,remaining=size),self.h.row(20,3,remaining=size,multi_bio=1)]
        rows += [self.meta('BLOCK_BIO',20,index=i,bio=3000+i,remaining=size,more=1) for i in range(8)]
        rows += [self.h.row(30,5,remaining=size,completed=size,multi_bio=1)]
        s=self.check(rows)['provenance']['issue_sources'][0]
        self.assertTrue(s['truncated']); self.assertEqual(s['unknown_bytes'],4096)

    def test_stale_identity_and_cyclic_bio_and_false_total_rejected(self):
        for changes in (dict(bio_owner_generation=2),dict(bio=3000),dict(bytes=2048),dict(index=8),
                        dict(bio_origin_overdepth=1),dict(more=1)):
            d=dict(remaining=8192,index=1,bio=3001); d.update(changes)
            rows=self.appended(); rows[4]=self.meta('BLOCK_BIO',30,**d); self.check(rows,'FAIL')

    def test_requeue_snapshots_are_not_added_as_new_bytes(self):
        rows=[self.h.row(10,1),self.h.row(20,3),self.meta('BLOCK_BIO',20),
              self.h.row(25,5,completed=2048),self.h.row(30,4,remaining=2048),
              self.h.row(40,3,remaining=2048),self.meta('BLOCK_BIO',40,remaining=2048,bytes=2048),
              self.h.row(50,5,remaining=2048,completed=2048)]
        p=self.check(rows)['provenance']
        self.assertEqual([s['remaining_bytes'] for s in p['issue_sources']],[4096,2048])
        self.assertNotIn('total_submitted_bytes',p)

    def test_legacy_raw_cannot_accept_new_metadata(self):
        r=self.h.run_rows(self.appended(),self.h.record())
        self.assertEqual(r['quality']['status'],'FAIL')

    def test_address_reuse_requires_actual_episode(self):
        rows=self.appended(); rows[4]['detail']=rows[4]['detail'].replace('episode_ns=10','episode_ns=9')
        self.check(rows,'FAIL')

    def test_empty_flush_needs_no_bio_snapshot(self):
        self.check([self.h.row(10,1,remaining=0,bio=0),self.h.row(20,3,remaining=0,bio=0),
                    self.h.row(30,5,remaining=0,completed=0,bio=0)])

    def test_merge_while_inflight_rejected(self):
        rows=[self.h.row(10,1),self.h.row(15,3),self.meta('BLOCK_BIO',15)]
        rows+=self.appended()[1:]
        self.check(rows,'FAIL')
