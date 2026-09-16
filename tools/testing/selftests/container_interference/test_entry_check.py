#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Parser regressions only; synthetic records are never runtime evidence."""
import json
import unittest
from entry_check import check


def fixture():
    lines = []
    for slot in range(8):
        lines.append(f'CIS_ENTRY_CONTAINER slot={slot} pid=1 host=cis-container readonly_root=1 cgroup=0::/cis-entry-{slot}')
        lines.append(f'CIS_ENTRY_WORKLOAD slot={slot} calls={0 if slot == 0 else 2000} loops_per_call=256 start_ns=1000000000 end_ns=4000000000 errors=0')
    lines += ['CIS_ENTRY_GUARD time_ns=2800000000 capture=0 errors=0 ',
              json.dumps({'kind': 'capture_policy', 'detail': 'entry_rate_limit=200000'}),
              json.dumps({'kind': 'entry_budget_disable', 'detail': 'configured_limit=200000 delta_entries=400000 interval_ns=1000000000 detaching_collectors=1'}),
              'CIS_ENTRY_STORM_RESULT failures=0 default_limit=200000',
              'CIS_ENTRY_STORM_FAILURES=0']
    return '\n'.join(lines)


class EntryCheck(unittest.TestCase):
    def test_complete_parser_fixture(self):
        self.assertTrue(check(fixture())['pass'])

    def test_duplicate_and_warning_rejected(self):
        source = fixture()
        self.assertFalse(check(source + '\n' + source.splitlines()[1])['pass'])
        self.assertFalse(check(source + '\n[ 10.0] WARNING: test warning')['pass'])

    def test_low_injected_threshold_not_production_stress(self):
        self.assertFalse(check(fixture().replace('configured_limit=200000', 'configured_limit=1'))['pass'])

    def test_early_exit_and_wrong_identity_rejected(self):
        self.assertFalse(check(fixture().replace('end_ns=4000000000', 'end_ns=2000000000'))['pass'])
        self.assertFalse(check(fixture().replace('pid=1 ', 'pid=2 '))['pass'])


if __name__ == '__main__':
    unittest.main()
