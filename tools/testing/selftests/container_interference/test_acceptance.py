#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest
from copy import deepcopy
PATH=pathlib.Path(__file__).resolve().parents[3]/'container_interference'/'acceptance.py'
sys.path.insert(0,str(PATH.parent))
SPEC=importlib.util.spec_from_file_location('acceptance',PATH)
MODULE=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(MODULE)


class Acceptance(unittest.TestCase):
    def test_implementation_is_not_acceptance(self):
        manifest={'stages':{s:{n:{'status':'IMPLEMENTED'} for n in names} for s,names in MODULE.REQUIRED.items()}}
        self.assertFalse(MODULE.check(manifest,pathlib.Path('.'))['complete'])

    def test_unsubstantiated_pass_rejected(self):
        manifest={'stages':{s:{n:{'status':'PASS'} for n in names} for s,names in MODULE.REQUIRED.items()}}
        result=MODULE.check(manifest,pathlib.Path('.'))
        self.assertFalse(result['complete']);self.assertTrue(result['errors'])

    def test_skip_never_satisfies_core(self):
        result=MODULE.check({'stages':{'S1':{'identity':{'status':'SKIP'}}}},pathlib.Path('.'))
        self.assertFalse(result['stages']['S1']['items']['identity']['accepted'])

    def test_numeric_gate_rejects_asserted_pass_and_wide_interval(self):
        report={'coverage_valid':True,'results':[
            {'workload':'open-loop','mode':'ip','role':role,'n':5,
             '95pct_interval':[-1,10],'threshold_percent':2,'status':'PASS'}
            for role in ('target','bystander')]}
        self.assertFalse(MODULE.performance_gate('S2','ambient_p99',[report]))
        for row in report['results']: row['95pct_interval']=[-1,1]
        self.assertTrue(MODULE.performance_gate('S2','ambient_p99',[report]))
        report['coverage_valid']=False
        self.assertFalse(MODULE.performance_gate('S2','ambient_p99',[report]))

    def test_two_container_screen_cannot_satisfy_scale_acceptance(self):
        report={'coverage_valid':True,'results':[
            {'workload':'bench','mode':'ip','role':role,'n':5,
             '95pct_interval':[-1,0.5],'threshold_percent':1,'containers':2}
            for role in ('target','bystander')]}
        self.assertTrue(MODULE.performance_gate('S2','ambient_throughput',[report]))
        self.assertFalse(MODULE.performance_gate('S6','ambient_throughput',[report]))

    def test_diagnostic_cost_must_cover_each_owner_collector(self):
        from profiles import fingerprint
        profile=json.loads((PATH.parent/'profile-candidate.json').read_text())
        digest=fingerprint(profile)
        report={'coverage_valid':True, 'profile_sha256':digest,
                'collector_coverage':{name:{'status':'PASS','eligible_episodes':10,
                    'observed_episodes':10,'wrong_relations':0,'evidence_protocol':2,
                    'paired_terminal_events':10,'raw_sha256':'a'*64} for name in profile['collectors']},
                'results':[]}
        for count in (1,12,24,48):
            for role in ('target','bystander') if count>1 else ('target',):
                for collector in ('owner_mutex','owner_dentry'):
                    report['results'].append({'workload':'bench','mode':'diag',
                        'family':'diagnostic','containers':count,'role':role,'collector':collector,
                        'profile_sha256':digest,'n':5,'95pct_interval':[-1,1],'threshold_percent':3})
        self.assertTrue(MODULE.performance_gate('S6','diagnostic_throughput',[report],profile))
        for mutation in ('missing','mislabeled','wide','foreign_profile'):
            bad=deepcopy(report)
            if mutation=='missing': bad['results'].pop()
            if mutation=='mislabeled': bad['results'][-1]['collector']='sched'
            if mutation=='wide': bad['results'][-1]['95pct_interval']=[-1,8]
            if mutation=='foreign_profile': bad['results'][-1]['profile_sha256']='b'*64
            self.assertFalse(MODULE.performance_gate('S6','diagnostic_throughput',[bad],profile))


if __name__=='__main__': unittest.main()
