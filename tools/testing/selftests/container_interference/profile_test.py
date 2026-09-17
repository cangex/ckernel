#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
import importlib.util
import json
from pathlib import Path
import unittest

root = Path(__file__).resolve().parents[3]/'container_interference'
spec = importlib.util.spec_from_file_location('cis_profile', root/'profiles.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class Profiles(unittest.TestCase):
    def setUp(self):
        self.profile=json.loads((root/'profile-candidate.json').read_text())
        self.report={'profile_sha256':p.fingerprint(self.profile), 'collector_coverage':{
            name:{'status':'PASS','eligible_episodes':10,'observed_episodes':10,
                  'wrong_relations':0,'raw_sha256':'a'*64,'evidence_protocol':2,
                  'paired_terminal_events':10} for name in self.profile['collectors']}}

    def test_bound_profile(self):
        self.assertTrue(p.collector_gate(self.report,self.profile,True))

    def test_legacy_and_sched_only_do_not_admit_owner(self):
        self.assertFalse(p.collector_gate({},self.profile,True))
        del self.report['collector_coverage']['owner_dentry']
        self.assertFalse(p.collector_gate(self.report,self.profile,True))

    def test_empty_collectors_and_wrong_relations_fail(self):
        for field,value in [('observed_episodes',0),('wrong_relations',1),('evidence_protocol',1),('paired_terminal_events',0)]:
            self.setUp()
            self.report['collector_coverage']['owner_mutex'][field]=value
            self.assertFalse(p.collector_gate(self.report,self.profile,True))

    def test_configuration_change_is_not_accepted(self):
        self.profile['ip_budget_hz']=2000
        self.assertFalse(p.collector_gate(self.report,self.profile))

    def test_a_single_correct_episode_does_not_satisfy_coverage(self):
        self.report['collector_coverage']['owner_mutex']['observed_episodes']=1
        self.assertFalse(p.collector_gate(self.report,self.profile,True))

    def test_non_hash_and_invalid_recall_fail_closed(self):
        self.report['collector_coverage']['owner_mutex']['raw_sha256']='z'*64
        self.assertFalse(p.collector_gate(self.report,self.profile,True))
        self.setUp()
        self.profile['eligible_end_to_end_recall']=float('nan')
        self.report['profile_sha256']=p.fingerprint(self.profile)
        self.assertFalse(p.collector_gate(self.report,self.profile,True))

    def test_malformed_counts_are_not_truthy_passes(self):
        for field in ('eligible_episodes','observed_episodes','wrong_relations','paired_terminal_events'):
            for value in (True, '10', -1, float('nan'), None):
                self.setUp()
                self.report['collector_coverage']['owner_mutex'][field]=value
                self.assertFalse(p.collector_gate(self.report,self.profile,True))
        self.assertFalse(p.collector_gate(None,self.profile,True))
        self.report['collector_coverage']=[]
        self.assertFalse(p.collector_gate(self.report,self.profile,True))


if __name__=='__main__':
    unittest.main()
