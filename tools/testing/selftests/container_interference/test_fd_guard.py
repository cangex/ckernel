# SPDX-License-Identifier: GPL-2.0
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'container_interference'))
from collector_manifest import contract
from fd_guard_check import check


class FDGuardTests(unittest.TestCase):
    def fixture(self):
        c=contract('fd')
        inventory=dict(schema='cis-loaded-inventory-v1',profile=6,map_names=c['maps'],program_names=c['programs'],
            maps=list(range(1,len(c['maps'])+1)),programs=[20,21],ip_perf_cpus=0)
        record=dict(collector='fd',session_id='1',inventory=inventory,result='PARTIAL',state='IDLE',
            finalized=True,objects_absent=True,requested_ns=100,window=dict(start_ns=200,end_ns=2200),
            receipt=dict(reason='ENTRY_RATE_LIMIT',result='PARTIAL'))
        raw=json.dumps(dict(session_id='1',kind='entry_budget_disable',
            detail='configured_limit=200000 delta_entries=300000 interval_ns=1000000000')).encode()
        logs=['\n'.join('CIS_FD_STORM '+json.dumps(dict(bucket=i,begin_ns=300+i*500,end_ns=800+i*500,operations=256,errors=0))
                         for i in range(8))]*2
        sources=dict(active=dict(before_ns=200,after_ns=201,expected_collector='fd',observed=dict(version='1',owner='0',fd='1')),
                     idle=dict(before_ns=1400,after_ns=1401,expected_collector=None,observed=dict(version='1',owner='0',fd='0')))
        return record,raw,logs,sources

    def test_guard_pass_is_rejected_capture_and_business_continuation(self):
        args=self.fixture();result=check(*args)
        self.assertEqual(result['status'],'PASS')
        self.assertEqual(result['capture_status'],'PARTIAL')
        args[0]['result']='COMPLETE'
        self.assertIn('capture_or_cleanup_state',check(*args)['errors'])

    def test_cannot_relax_threshold_or_hide_source_left_enabled(self):
        record,raw,logs,sources=self.fixture()
        self.assertIn('missing_fixed_rate_proof',check(record,raw.replace(b'200000',b'900000'),logs,sources)['errors'])
        sources['idle']['observed']['fd']='1'
        with self.assertRaises(ValueError): check(record,raw,logs,sources)

    def test_completed_business_before_detach_is_not_continuation(self):
        args=self.fixture();args[3]['idle'].update(before_ns=5000,after_ns=5001)
        self.assertIn('no_business_progress_after_source_detach',check(*args)['errors'])


if __name__=='__main__': unittest.main()
