# SPDX-License-Identifier: GPL-2.0
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'container_interference'))
from kernel_resource_audit import analyze_session


class KernelResource(unittest.TestCase):
    record=dict(session_id=1, inventory=dict(maps=[2], programs=[3]), objects_absent=True)

    def stream(self):
        details=['object_type=map object_id=2 info_valid=1 fdinfo_valid=1 fdinfo_bytes=4096 map_type=1 key_bytes=8 value_bytes=16 max_entries=128 map_flags=0 allocation_upper_bound_known=0',
                 'object_type=program object_id=3 info_valid=1 fdinfo_valid=1 fdinfo_bytes=8192 jit_code_bytes=100 xlated_bytes=120 btf_id=4 nr_map_ids=1 allocation_upper_bound_known=0']
        return '\n'.join(json.dumps(dict(session_id=1,kind='kernel_object_inventory',detail=x)) for x in details)

    def test_payload_not_upper_bound_or_reclaim(self):
        value=analyze_session(self.record,self.stream())
        self.assertEqual(value['inventory_status'],'PASS')
        self.assertEqual(value['jit_code_bytes'],100)
        self.assertFalse(value['total_memory_complete'])
        self.assertIsNone(value['reclaim_completed'])

    def test_missing_zero_duplicates_or_wrong_session(self):
        self.assertEqual(analyze_session(self.record,'')['inventory_status'],'BLOCKED')
        self.assertEqual(analyze_session(self.record,self.stream().replace('fdinfo_valid=1','fdinfo_valid=0'))['inventory_status'],'BLOCKED')
        for stream in [self.stream()+'\n'+self.stream(),self.stream().replace('"session_id": 1','"session_id": 2'),self.stream().replace('allocation_upper_bound_known=0','allocation_upper_bound_known=1')]:
            with self.assertRaises(ValueError):analyze_session(self.record,stream)

    def test_different_session_can_reuse_ids(self):
        second=dict(self.record,session_id=2)
        self.assertEqual(analyze_session(second,self.stream().replace('"session_id": 1','"session_id": 2'))['inventory_status'],'PASS')

    def test_inventory_journal_mismatch(self):
        self.assertEqual(analyze_session(self.record,self.stream().replace('object_id=2','object_id=5'))['inventory_status'],'FAIL')


if __name__=='__main__':unittest.main()
