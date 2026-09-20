# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'container_interference'))
import resource_policy as rp
from collector_manifest import contract
from diagnosis_plan import recommend
from source_switches import expected_fields


class PublicResourcePolicyTests(unittest.TestCase):
    def test_default_rejects_private_extensions(self):
        for name in rp.EXTENSIONS:
            with self.subTest(collector=name), self.assertRaises(PermissionError):
                rp.admit(rp.policy(), name)
        for name in rp.DEFAULT:
            rp.admit(rp.policy(), name)

    def test_extension_is_manual_only_and_bound_to_policy(self):
        value = rp.policy(['fd'])
        rp.admit(value, 'fd')
        with self.assertRaises(PermissionError): rp.admit(value, 'fd', automatic=True)
        self.assertNotEqual(rp.fingerprint(value), rp.fingerprint(rp.policy()))
        value['automatic'].append('fd')
        with self.assertRaises(ValueError): rp.admit(value, 'fd', automatic=True)
        for extensions in (['fd', 'fd'], ['not-a-collector'], 'fd', [True]):
            with self.assertRaises(ValueError): rp.policy(extensions)

    def test_private_hotspot_no_longer_routes(self):
        for symbol in ('alloc_fd', 'close_fd_get_file', 'lock_sock', 'tcp_sendmsg',
                       'skb_release_all', 'mutex_lock', 'lockref_put_return',
                       'rwsem_down_write_slowpath', 'native_queued_spin_lock_slowpath'):
            report = dict(quality=dict(status='PASS'), session_id='7', survey_epoch=1,
                          window=dict(end_ns=99), candidates=[dict(valid=True,
                          target='1:1', top_ip=[dict(symbol=symbol)], rates={})])
            self.assertEqual(recommend(report), [], symbol)
        report['candidates'][0]['top_ip'] = [dict(symbol='kmem_cache_alloc')]
        self.assertEqual(recommend(report)[0]['collector'], 'alloc_backend')

    def test_backend_has_no_tree_program_map_or_source(self):
        backend = contract('alloc_backend')
        self.assertEqual(backend['programs'], ['alloc_step', 'alloc_release'])
        self.assertNotIn('maple_pending', backend['maps'])
        self.assertIn('maple_pending', contract('allocator')['maps'])
        fields = expected_fields('14', 'alloc_backend')
        self.assertEqual(fields['allocator'], '1')
        self.assertEqual(fields['allocator_release'], '1')
        for source in ('maple', 'fd', 'owner', 'net', 'net_tx', 'rwsem'):
            self.assertEqual(fields[source], '0')


if __name__ == '__main__': unittest.main()
