# SPDX-License-Identifier: GPL-2.0
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'container_interference'))
import collector_manifest as cm
import collector_audit
import relations
from periodic_plan import digest


class CollectorContract(unittest.TestCase):
    def inventory(self, name):
        c = cm.contract(name)
        return dict(schema='cis-loaded-inventory-v1', profile=c['profile'],
                    maps=list(range(1, len(c['maps'])+1)), map_names=c['maps'],
                    programs=list(range(101, 101+len(c['programs']))), program_names=c['programs'],
                    ip_perf_cpus=8 if name == 'ip' else 0)

    def test_exact_load(self):
        for name in cm.COLLECTORS:
            self.assertEqual(cm.validate_inventory(name, self.inventory(name)), digest(cm.contract(name)))

    def test_fail_closed_inventory(self):
        for field, value in [('schema', 'future'), ('profile', 2), ('maps', [1]),
                             ('map_names', ['roots']), ('program_names', ['sample_ip', 'owner_state']),
                             ('ip_perf_cpus', 0), ('ip_perf_cpus', True)]:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                cm.validate_inventory('ip', dict(self.inventory('ip'), **{field: value}))
        inv = self.inventory('reclaim')
        inv['programs'][1] = inv['programs'][0]
        with self.assertRaises(ValueError): cm.validate_inventory('reclaim', inv)

    def test_bundle_is_content_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'cis.bpf.o'
            for name in cm.COLLECTORS: cm.object_path(p, name).write_bytes(b'old')
            old = digest(cm.bundle_manifest(p))
            cm.object_path(p, 'owner').write_bytes(b'new')
            self.assertNotEqual(old, digest(cm.bundle_manifest(p)))
        cm.contract('ip')['maps'].append('wrong')
        self.assertNotIn('wrong', cm.contract('ip')['maps'])
        with self.assertRaises(ValueError): cm.contract('tcp')

    def test_network_historical_contracts_are_exact_and_replay_only(self):
        for old in (cm.LEGACY_NET_PROCESS,cm.LEGACY_NET_TX,cm.LEGACY_NET,cm.LEGACY_NET_USE_ONLY):
            c=cm.contract('net'); c.update(copy.deepcopy(old))
            inv=self.inventory('net')
            inv.update(map_names=c['maps'],maps=list(range(1,len(c['maps'])+1)),
                       program_names=c['programs'],programs=list(range(101,101+len(c['programs']))))
            r=dict(collector='net',inventory=inv,collector_contract_sha256=digest(c))
            self.assertEqual(cm.validate_record_inventory(r),digest(c))
            with self.assertRaises(ValueError): cm.validate_inventory('net',inv)
            with self.assertRaises(ValueError): cm.validate_record_inventory(dict(r,collector_contract_sha256='0'*64))
            if old==cm.LEGACY_NET_USE_ONLY:
                self.assertEqual(digest(c),'04afe782d748307d8bbd97be9ac499652bea0b737730b508a1105e01930d05d3')

    def test_missing_scope_not_zero(self):
        row = dict(collector='ip', session_id='1', inventory=self.inventory('ip'))
        out = collector_audit.audit(row, b'')
        self.assertEqual(out['status'], 'BLOCKED')
        self.assertIsNone(out['counters']['terminal_scope']['unknown'])
        self.assertIsNone(out['population_coverage'])
        with self.assertRaises(ValueError): collector_audit.audit(row, b'{"session_id":"2"}')

    def test_fd_prefix_history_is_exact_and_read_only(self):
        old=cm.contract('fd'); old.update(copy.deepcopy(cm.LEGACY_FD))
        inventory=self.inventory('fd')
        record=dict(collector='fd',inventory=inventory,collector_contract_sha256=digest(old))
        self.assertIn('prefix-64',old['source_filter'])
        self.assertIn('prefix-128',cm.contract('fd')['source_filter'])
        self.assertEqual(cm.validate_record_inventory(record),digest(old))
        self.assertNotEqual(cm.validate_inventory('fd',inventory),digest(old))
        with self.assertRaises(ValueError):
            cm.validate_record_inventory(dict(record,collector_contract_sha256='0'*64))
        for name in ('fd','owner','slub'):
            self.assertEqual(cm.contract(name)['limits']['entry_rate_per_s'],200000)
            self.assertEqual(cm.contract(name)['limits']['output_bytes'],16<<20)
        self.assertIn('prefix 64',cm.contract('owner')['source_filter'])
        self.assertIn('prefix-64',cm.contract('slub')['source_filter'])

    def test_independent_fd_inventory_and_resources(self):
        self.assertNotEqual(cm.contract('owner')['profile'],cm.contract('fd')['profile'])
        with self.assertRaises(ValueError): cm.validate_inventory('owner',self.inventory('fd'))
        with self.assertRaises(ValueError): cm.validate_inventory('fd',self.inventory('owner'))
        for name,allowed,wrong in (('fd',3,1),('owner',2,3)):
            record=dict(collector=name,session_id='1',inventory=self.inventory(name),
                        collector_contract_sha256=digest(cm.contract(name)))
            raw=lambda resource: json.dumps(dict(session_id='1',kind='OWNER',detail='resource=%d'%resource)).encode()
            self.assertEqual(collector_audit.audit(record,raw(allowed))['errors'],[])
            self.assertEqual(collector_audit.audit(record,raw(wrong))['status'],'FAIL')


class RelationContract(unittest.TestCase):
    def relation(self, model='holder_waiter'):
        roles = dict(holder_waiter=['holder', 'waiter'], shared_updates=['contributor'],
                     queue_service=['submitter', 'executor'])[model]
        return dict(schema='cis-relations-v3', model=model, evidence='E2', session_epoch='one',
                    object=dict(kind='example', id='0x123', lifetime_epoch='create7', lifetime_proof='pinned'),
                    participants=[dict(role=r, container_id=5+i, generation=1, task_id=123+i) for i,r in enumerate(roles)],
                    intervals=[dict(phase='wait', start_ns=10, end_ns=30, metric='wall_ns', value=20)],
                    unknown=[], causal_validation=None)

    def test_three_models(self):
        for model in relations.MODELS:
            row = self.relation(model)
            self.assertEqual(row, relations.validate(row))

    def test_no_counter_holder_or_false_causality(self):
        row = self.relation('shared_updates'); row['participants'][0]['role'] = 'holder'
        with self.assertRaises(ValueError): relations.validate(row)
        row = self.relation(); row['evidence'] = 'E3'
        with self.assertRaises(ValueError): relations.validate(row)
        row['causal_validation'] = dict(artifact_sha256='a'*64, controlled_intervention=True)
        relations.validate(row)

    def test_lifetime_and_unknown(self):
        row = self.relation(); row['object']['lifetime_proof'] = 'unknown'
        with self.assertRaises(ValueError): relations.validate(row)
        row['evidence'] = 'E1'; relations.validate(row)
        row = self.relation(); row['participants'][0]['container_id'] = None
        with self.assertRaises(ValueError): relations.validate(row)

    def test_time_and_bounds(self):
        for metric, value in [('wall_ns', 19), ('on_cpu_ns', 21), ('spin_ns', 20)]:
            row = self.relation(); row['intervals'][0].update(metric=metric, value=value)
            with self.assertRaises(ValueError): relations.validate(row)
        for field,value in [('schema', 'cis-relations-v99'), ('participants', [{}]*33),
                            ('unknown', ['x']*65), ('intervals', [{}]*65)]:
            with self.assertRaises(ValueError): relations.validate(dict(self.relation(), **{field: value}))


if __name__ == '__main__': unittest.main()
