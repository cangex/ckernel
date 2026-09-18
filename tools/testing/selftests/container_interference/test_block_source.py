# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import unittest
from source_switches import expected_fields

ROOT=Path(__file__).resolve().parents[4]


class BlockSources(unittest.TestCase):
    def test_existing_native_request_tracepoints_and_partial_completion(self):
        trace=(ROOT/'include/trace/events/block.h').read_text()
        mq=(ROOT/'block/blk-mq.c').read_text()
        for name in ('block_io_start','block_rq_insert','block_rq_issue','block_rq_requeue',
                     'block_rq_complete','block_rq_merge','block_rq_remap'):
            self.assertIn(name,trace)
        self.assertIn('trace_block_rq_complete(req, error, nr_bytes)',mq)
        self.assertIn('trace_block_io_start(req)',mq)
        self.assertIn('if (blk_mq_need_time_stamp(rq))',mq)
        self.assertIn('req->start_time_ns = next->start_time_ns', (ROOT/'block/blk-merge.c').read_text())

    def test_full_switch_visibility_and_legacy_not_silently_accepted(self):
        fields=expected_fields('6','block')
        self.assertEqual(sum(int(v) for k,v in fields.items() if k!='version'),7)
        self.assertTrue(all(v=='0' for k,v in expected_fields('6',None).items() if k!='version'))
        with self.assertRaises(ValueError): expected_fields('5','block')
        text=(ROOT/'kernel/locking/cis_observe.c').read_text()
        self.assertIn('trace_cis_rwsem_state_enabled() || cis_block_active()',text)
        self.assertIn('trace_cis_net_skb_release_enabled() ||',text)
        self.assertIn('tracepoint_synchronize_unregister()',text)
