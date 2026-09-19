# SPDX-License-Identifier: GPL-2.0
import copy
import json
from pathlib import Path
import unittest
from allocator_report import analyze
import test_allocator_report
from unified_report import markdown


class MapleReport(unittest.TestCase):
    def setup_rows(self):
        helper = test_allocator_report.AllocatorReport()
        d = dict(protocol=1, sample_time_ns=28, begin_ns=8, call_ns=10, tid=102,
                 task_start=1, cpu=1, tree=700, cache=100, operation=1, gfp=64, requested=1, count=1)
        row = dict(session_id='7', kind='MAPLE_ALLOC', id=1, generation=1,
                   detail=' '.join('%s=%s' % p for p in d.items()))
        return helper.record(), helper.rows() + [row]

    def run_rows(self, record, rows):
        terminal=[dict(session_id='7',kind=k,detail=v) for k,v in (
            ('terminal_counters','received=1 emitted=1 rejected=0'),
            ('terminal_coverage','lost=0 owner_skipped=0'),
            ('terminal_scope','unknown=0 overdepth=0 unmatched=0 nested=0 expired=0 irq_context=0'),
            ('owner_entry_stages','owner_entries=0 sched_entries=0 target_waits=0 watch_events=0'))]
        return analyze(record, '\n'.join(json.dumps(r) for r in rows+terminal).encode())

    def test_tree_is_not_cache_or_node_and_allows_cpu_migration(self):
        r, rows = self.setup_rows()
        value = self.run_rows(r, rows)
        self.assertEqual(value['maple']['status'], 'PASS')
        call = value['calls'][0]
        self.assertEqual(call['maple_context']['tree_address'], 700)
        self.assertEqual(call['cache_address'], 100)
        self.assertEqual(call['object_address'], 500)
        self.assertEqual(call['maple_context']['tree_owner'], 'UNKNOWN')
        self.assertIsNone(call['maple_context']['blocking_container'])

    def test_mismatch_duplicate_or_missing_backend_does_not_create_identity(self):
        for old, new in [('cache=100','cache=101'), ('count=1','count=0'),
                         ('begin_ns=8','begin_ns=11'), ('sample_time_ns=28','sample_time_ns=12'),
                         ('gfp=64','gfp=65'), ('call_ns=10','call_ns=12'), ('tid=102','tid=103')]:
            r, rows = self.setup_rows()
            rows[-1]['detail'] = rows[-1]['detail'].replace(old,new)
            value = self.run_rows(r,rows)
            self.assertEqual(value['maple']['status'],'FAIL',(old,new))
            self.assertFalse(value['maple']['contexts'])
            self.assertIsNone(value['calls'][0]['maple_context'])
        r, rows = self.setup_rows()
        rows.append(copy.deepcopy(rows[-1]))
        self.assertEqual(self.run_rows(r,rows)['maple']['status'],'FAIL')

    def test_absent_or_corrupt_capture_is_not_guessed_from_stack(self):
        r, rows = self.setup_rows()
        self.assertIsNone(self.run_rows(r,rows[:-1])['calls'][0]['maple_context'])
        r['result']='PARTIAL'
        self.assertFalse(self.run_rows(r,rows)['maple']['contexts'])

    def test_same_address_in_later_call_is_separate_bracket_not_lifetime(self):
        r, rows = self.setup_rows()
        later = copy.deepcopy(rows)
        for row in later:
            parts=dict(p.split('=') for p in row['detail'].split())
            for k in ('sample_time_ns','begin_ns','call_ns'):
                if k in parts: parts[k]=str(int(parts[k])+30)
            row['detail']=' '.join('%s=%s'%p for p in parts.items())
        r['window']['end_ns']=100
        # Widen only the synthetic test window, not any live record.
        value=self.run_rows(r,rows+later)
        self.assertEqual(len(value['maple']['contexts']),2)
        self.assertNotEqual(*[c['allocation_bracket_ns'] for c in value['maple']['contexts']])

    def test_duplication_uses_destination_and_free_never_uses_current_tree(self):
        root=Path(__file__).resolve().parents[4]
        text=(root/'lib/maple_tree.c').read_text()
        self.assertIn('mt_alloc_one(new_mas->tree, gfp)',text)
        self.assertIn('mt_alloc_bulk(new_mas->tree, gfp, request',text)
        self.assertIn('mt_alloc_one(mas->tree, gfp)',text)
        release=text.split('static void mt_free_rcu(',1)[1].split('\n}',1)[0]
        self.assertNotIn('current',release)
        self.assertNotIn('cis_maple',release)

    def test_nesting_and_backend_reentry_fail_closed(self):
        root=Path(__file__).resolve().parents[4]
        text=(root/'tools/container_interference/bpf/maple.bpf.h').read_text()
        self.assertIn('COUNT(s, nested)',text)
        self.assertIn('if (saved->base.weight ||',text)
        self.assertIn('bpf_map_delete_elem(&maple_pending, &key)',text)
        self.assertNotIn('BPF_ANY',text)

    def test_readable_report_keeps_the_identity_boundary(self):
        r,rows=self.setup_rows()
        context=self.run_rows(r,rows)['calls'][0]['maple_context']
        report=dict(session_id='7',collector='allocator',quality=dict(status='PASS'),relations=[dict(
            relation='allocation_stages',evidence='E1',affected_actor=[1,1],resource=dict(address=100),
            participants=[],chain_leaf_to_root=[],details=dict(maple_allocation_context=context))])
        rendered=markdown(report)
        self.assertIn('Maple目标树',rendered)
        self.assertIn('树地址仅在本次申请内有效',rendered)
