#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
import importlib.util
import json
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[3] / 'container_interference/session.py'
spec = importlib.util.spec_from_file_location('session', path)
session = importlib.util.module_from_spec(spec)
spec.loader.exec_module(session)

def start(**changes):
    value = dict(version=1, op='start', nonce='abc', collector='ip', targets=['1:2'], window_ms=2000)
    value.update(changes)
    return value

class Contract(unittest.TestCase):
    def test_valid_collectors(self):
        for collector in ('ip', 'owner'):
            self.assertEqual(session.validate(start(collector=collector))['collector'], collector)

    def test_version(self):
        for version in (0, 2, None, '1', True):
            with self.assertRaises(ValueError): session.validate(start(version=version))

    def test_target_capacity(self):
        for targets in ([], ['1:2', '1:2'], ['1:2', '3:4', '5:6'], [{}], [1]):
            with self.assertRaises(ValueError): session.validate(start(targets=targets))

    def test_window(self):
        for window in (0, -1, 10001, True, '2000'):
            with self.assertRaises(ValueError): session.validate(start(window_ms=window))

    def test_no_implicit_collectors(self):
        with self.assertRaises(ValueError): session.validate(start(collector='auto'))

    def test_no_unknown_fields(self):
        with self.assertRaises(ValueError): session.validate(start(fallback=True))

    def test_nonce(self):
        for nonce in ('', 'a'*65, '../escape'):
            with self.assertRaises(ValueError): session.validate(start(nonce=nonce))

    def test_cancel_scoped(self):
        self.assertEqual(session.validate(dict(version=1, op='cancel', session='123'))['session'], '123')

    def test_injection_bounded(self):
        with self.assertRaises(ValueError): session.validate(start(inject='run_shell'))

    def test_json_roundtrip(self):
        self.assertEqual(json.loads(session.encoded(start())), start())

if __name__ == '__main__': unittest.main()
