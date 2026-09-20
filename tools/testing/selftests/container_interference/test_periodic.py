# SPDX-License-Identifier: GPL-2.0
import json
from pathlib import Path
import sys
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parents[3] / 'container_interference'
sys.path.insert(0, str(TOOLS))
from periodic_plan import P1_CHECKS, capacity, require_acceptance, validate_plan
from periodic_report import REQUIRED, completion, cycle_cost, paired_cost
from process_budget import ProcessBudget
from schedule import Schedule
import survey


class Clock:
    def __init__(self): self.ns = 1_000_000_000
    def __call__(self): return self.ns
    def advance(self, seconds): self.ns += int(seconds*1e9)


def boundary(time_ns, value=10, generation=2):
    return dict(id=1, generation=generation, identity_valid=True,
                config={name: 'test' for name in survey.CONFIG},
                files={name: dict(start_ns=time_ns, end_ns=time_ns+10,
                                 counters={'usage_usec': value} if name == 'cpu.stat' else {'some_total_usec': value})
                       for name in survey.COUNTERS})


class PlanTests(unittest.TestCase):
    def test_strict_types_and_unknown(self):
        for plan in ({'interval_s': True}, {'interval_s': 1}, {'interval_s': float('nan')},
                     {'targets_per_session': 3}, {'automatic_owner': True}, {'disk_bytes': 0}, []):
            with self.assertRaises(ValueError): validate_plan(plan)

    def test_capacity_not_detection_promise(self):
        result = capacity(validate_plan({}), 256)
        self.assertEqual(result['ideal_round_s'], 128*60)
        self.assertFalse(result['sample_age_guaranteed'])
        self.assertFalse(capacity(validate_plan({'max_sample_age_s': 60}), 256)['capacity_admissible'])

    def test_admission_does_not_accept_implementation(self):
        manifest = dict(controller_sha256='a', worker_sha256='b', bpf_sha256='c',
                        support_sha256='d', kernel_release='e', kernel_notes_sha256='f', residue_sha256='g',
                        kernel_cmdline_sha256='h')
        value = dict(schema='cis-p1-admission-v2', source=manifest, phase_complete=True,
                     checks={key: 'PASS' for key in P1_CHECKS}, evidence_index_sha256='0'*64)
        self.assertEqual(len(require_acceptance(value, manifest)), 64)
        for field, change in (('phase_complete', False), ('checks', {'idle_p99': 'PASS'}),
                              ('source', dict(manifest, worker_sha256='different')),
                              ('source', dict(manifest, kernel_cmdline_sha256='gate_changed')),
                              ('evidence_index_sha256', 'x'*64)):
            with self.assertRaises(ValueError): require_acceptance(dict(value, **{field: change}), manifest)

    def test_completion_requires_all_gates(self):
        self.assertFalse(completion({'scheduler_model': 'PASS'})['phase_complete'])
        self.assertFalse(completion({key: 'PASS' for key in REQUIRED})['phase_complete'])
        with self.assertRaises(ValueError): completion({'periodic_runtime': 'IMPLEMENTED'})

    def test_cost_interval_not_just_favorable_mean(self):
        pairs = [dict(off=100, on=value) for value in (90, 110, 90, 110, 100)]
        self.assertEqual(paired_cost(pairs, 'p99', 2)['status'], 'BLOCKED')
        self.assertEqual(paired_cost(pairs[:4], 'p99', 2)['status'], 'BLOCKED')
        self.assertEqual(paired_cost([dict(off=100, on=95)]*5, 'throughput', 1)['status'], 'FAIL')

    def test_bad_cost_pair_not_discarded(self):
        for value in (None, float('nan'), float('inf'), 0, True):
            pairs = [dict(off=100, on=100)]*4+[dict(off=100, on=value)]
            self.assertEqual(paired_cost(pairs, 'throughput', 1)['status'], 'BLOCKED')

    def test_no_business_cost_inference(self):
        result = cycle_cost(120_000_000, None, 60_000_000_000)
        self.assertEqual(result['process_cpu_one_cpu_pct'], .2)
        self.assertIsNone(result['total_cpu_one_cpu_pct'])
        self.assertFalse(result['business_overhead_inferred'])


class ScheduleTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.s = Schedule({'jitter_ms': 0}, self.clock)

    def tick(self):
        self.clock.ns = self.s.next_ns
        proposal = self.s.poll()
        if proposal:
            self.s.admit(proposal['targets'])
            for key in proposal['targets']:
                self.s.outcome(key, complete=True, valid=True)
        return proposal

    def test_idle_has_no_timer(self):
        self.assertIsNone(self.s.timeout())
        self.s.add('a')
        self.clock.advance(3600)
        self.assertIsNone(self.s.poll())

    def test_256_fair_rotation(self):
        for i in range(256): self.s.add(str(i))
        self.s.enable()
        seen = set()
        for _ in range(128): seen.update(self.tick()['targets'])
        self.assertEqual(len(seen), 256)

    def test_candidate_does_not_starve_ordinary(self):
        for i in range(256): self.s.add(str(i))
        self.s.enable()
        seen = set()
        for _ in range(256):
            self.s.roots['0']['candidate'] = True
            seen.update(self.tick()['targets'])
        self.assertEqual(len(seen), 256)

    def test_no_sample_is_not_healthy(self):
        self.s.add('a')
        self.s.outcome('a', complete=True, valid=False)
        value = self.s.status()['roots']['a']
        self.assertIsNotNone(value['served_ns'])
        self.assertIsNone(value['sample_age_s'])

    def test_missed_slots_never_burst(self):
        self.s.add('a')
        self.s.enable()
        self.clock.advance(600)
        self.assertIsNotNone(self.s.poll())
        self.assertIsNone(self.s.poll())
        self.assertEqual(self.s.skips['missed_slots'], 9)

    def test_active_cleanup_skips(self):
        self.s.add('a')
        self.s.enable()
        self.clock.advance(60)
        self.assertIsNone(self.s.poll('active_or_draining'))
        self.assertEqual(self.s.skips['active_or_draining'], 1)
        self.assertEqual(self.s.roots['a']['attempted_ns'], None)

    def test_manual_shares_budget_even_paused(self):
        self.s.add('a')
        self.s.admit(['a'], manual=True)
        self.s.pause()
        with self.assertRaises(ValueError): self.s.admit(['a'], manual=True)
        self.clock.advance(60)
        self.s.admit(['a'])

    def test_restart_does_not_catch_up(self):
        self.s.add('a')
        self.s.enable()
        self.clock.advance(600)
        self.s.pause()
        self.s.enable()
        self.assertIsNone(self.s.poll())
        self.assertEqual(self.s.timeout(), 60)

    def test_removed_or_unavailable_not_selected(self):
        self.s.add('a'); self.s.add('b')
        self.s.outcome('a', unavailable=True)
        self.s.remove('b')
        self.s.enable()
        self.clock.advance(60)
        self.assertIsNone(self.s.poll())

    def test_requested_capacity_rejected(self):
        limited = Schedule({'max_sample_age_s': 61}, self.clock)
        limited.add('a')
        with self.assertRaises(ValueError): limited.add('b')

    def test_jitter_reproducible(self):
        a, b = Schedule({}, self.clock), Schedule({}, self.clock)
        self.assertEqual([a.delay() for _ in range(50)], [b.delay() for _ in range(50)])

    def test_audit_memory_bounded(self):
        self.s.enable()
        for _ in range(1000):
            self.clock.ns = self.s.next_ns
            self.s.poll('busy')
        self.assertEqual(len(self.s.recent), 64)


class BudgetTests(unittest.TestCase):
    def test_phase_audit_keeps_violation_without_changing_limits(self):
        budget = ProcessBudget(0, 2000)
        budget.check(100_000_000, 'CAPTURING')
        budget.check(141_000_000, 'DRAIN')
        budget.check(150_000_000, 'VERIFY')
        audit = budget.snapshot()
        self.assertEqual(audit['phase_limits_ns']['CAPTURING'], 40_000_000)
        self.assertEqual(audit['phase_peak_cpu_ns']['CAPTURING'], 41_000_000)
        self.assertEqual(audit['phase_peak_cpu_ns']['DRAIN'], 9_000_000)
        self.assertEqual(audit['first_violation']['phase_cpu_ns'], 41_000_000)
        audit['phase_peak_cpu_ns']['DRAIN'] = 0
        self.assertEqual(budget.snapshot()['phase_peak_cpu_ns']['DRAIN'], 9_000_000)

    def test_capture_budget_includes_parent(self):
        budget = ProcessBudget(0, 2000)
        self.assertIsNone(budget.check(100_000_000, 'CAPTURING'))
        self.assertEqual(budget.check(141_000_000, 'CAPTURING'), 'COMBINED_PROCESS_CPU_CAPTURING')

    def test_transition_does_not_reset_violation(self):
        budget = ProcessBudget(0, 2000)
        self.assertEqual(budget.check(251_000_000, 'CAPTURING'), 'COMBINED_PROCESS_CPU_PREPARE')
        self.assertEqual(budget.check(251_000_001, 'VERIFY'), 'COMBINED_PROCESS_CPU_PREPARE')

    def test_total_not_reset_by_stage(self):
        budget = ProcessBudget(0, 2000)
        budget.check(200_000_000, 'CAPTURING')
        budget.check(230_000_000, 'DRAIN')
        self.assertEqual(budget.check(601_000_000, 'VERIFY'), 'COMBINED_PROCESS_CPU_TOTAL')


class SurveyTests(unittest.TestCase):
    def test_boundary_reset_and_identity(self):
        a = boundary(100)
        self.assertEqual(survey.boundary_delta(a, boundary(10000, 20))['status'], 'VALID')
        self.assertEqual(survey.boundary_delta(a, boundary(10000, 0))['status'], 'COUNTER_RESET_OR_BAD_TIME')
        self.assertEqual(survey.boundary_delta(a, boundary(10000, 20, generation=3))['status'], 'IDENTITY_UNKNOWN')

    def test_config_change_and_missing_not_zero(self):
        a, b = boundary(100), boundary(10000, 20)
        del b['files']['cpu.stat']
        result = survey.boundary_delta(a, b)
        self.assertEqual(result['status'], 'PARTIAL')
        self.assertIsNone(survey.rate(result, 'cpu.stat', 'usage_usec'))
        b['config']['cpu.max'] = 'changed'
        self.assertEqual(survey.boundary_delta(a, b)['status'], 'CONFIG_CHANGED')

    def data(self):
        record = dict(session_id='7', root_identities={'a': dict(id=1, generation=2)},
                      window=dict(start_ns=1000, end_ns=2000), result='COMPLETE',
                      objects_absent=True, receipt={}, boundary_before={'a': boundary(100)},
                      boundary_after={'a': boundary(10000, 20)}, source_identity={})
        meta = dict(session_id=7, kind='ip_event', detail='cpu=0 unit=kernel_cycles sample_period=100')
        event = dict(session_id=7, kind='IP', id=1, generation=2,
                     detail='sample_time_ns=1500 weight=100 cpu=0 ip=0xabc symbol=lookup')
        return record, meta, event

    def summarize(self, records, events, previous=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'raw.jsonl'
            path.write_text(''.join(json.dumps(event)+'\n' for event in events))
            return survey.summarize(records, path, previous or {}, 1)

    def test_first_sample_reference_not_anomaly(self):
        record, meta, event = self.data()
        result = self.summarize(record, [meta, event])['roots']['a']
        self.assertEqual(result['status'], 'REFERENCE')
        self.assertFalse(result['candidate'])

    def test_epoch_change_not_comparable(self):
        record, meta, event = self.data()
        previous = self.summarize(record, [meta, event])['roots']
        self.assertEqual(self.summarize(record, [meta, event], previous)['roots']['a']['status'], 'COMPARABLE')
        record['survey_epoch'] = 2
        self.assertEqual(self.summarize(record, [meta, event], previous)['roots']['a']['status'], 'REFERENCE')

    def test_topology_change_starts_new_reference_and_partial_cannot_compare(self):
        from test_resource_topology import endpoint
        from periodic_plan import digest
        from resource_topology import FINGERPRINT_FIELDS
        record,meta,event=self.data()
        a=endpoint(id=1,generation=2)
        record['boundary_before']['a']['topology']=a
        record['boundary_after']['a']['topology']=a
        previous=self.summarize(record,[meta,event])['roots']
        self.assertEqual(self.summarize(record,[meta,event],previous)['roots']['a']['status'],'COMPARABLE')
        b=endpoint(id=1,generation=2,device='8:1')
        record['boundary_before']['a']['topology']=b
        record['boundary_after']['a']['topology']=b
        self.assertEqual(self.summarize(record,[meta,event],previous)['roots']['a']['status'],'REFERENCE')
        b['status']='PARTIAL'
        b['fingerprint']=digest({k:b[k] for k in FINGERPRINT_FIELDS})
        previous=self.summarize(record,[meta,event])['roots']
        result=self.summarize(record,[meta,event],previous)['roots']['a']
        self.assertTrue(result['valid'])
        self.assertEqual(result['status'],'REFERENCE')
        self.assertFalse(result['candidate'])

    def test_no_sample_not_normal(self):
        record, meta, _ = self.data()
        self.assertFalse(self.summarize(record, [meta])['roots']['a']['valid'])

    def test_unknown_generation_not_reassigned(self):
        record, meta, event = self.data()
        event['generation'] = 999
        result = self.summarize(record, [meta, event])
        self.assertEqual(result['quality']['unknown_identity'], 1)
        self.assertFalse(result['roots']['a']['valid'])

    def test_cross_session_rejected(self):
        record, meta, event = self.data()
        event['session_id'] = 8
        with self.assertRaises(ValueError): self.summarize(record, [meta, event])

    def test_legacy_pmu_unit_not_assumed(self):
        record, _, event = self.data()
        self.assertFalse(self.summarize(record, [event])['roots']['a']['valid'])

    def test_window_truncation_not_zero_cost(self):
        record, meta, event = self.data()
        event['detail'] = event['detail'].replace('1500', '2500')
        result = self.summarize(record, [meta, event])
        self.assertEqual(result['quality']['outside_window_or_bad_weight'], 1)
        self.assertFalse(result['roots']['a']['valid'])


if __name__ == '__main__':
    unittest.main()
