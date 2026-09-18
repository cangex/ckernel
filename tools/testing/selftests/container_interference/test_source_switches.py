# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'container_interference'))
from source_switches import observe,validate


class SourceSwitchTests(unittest.TestCase):
    def test_sources_separate_and_both_disabled_when_idle(self):
        for name,owner,fd in (('owner',1,0),('fd',0,1),(None,0,0),('sync',0,0)):
            with patch('source_switches.Path.read_text',return_value='version=1 owner=%d fd=%d\n'%(owner,fd)):
                record=observe(name)
                validate(record,name,0,2**64-1)
                with self.assertRaises(ValueError): validate(record,name,record['after_ns']+1,2**64-1)
        for name in ('owner','fd',None):
            with patch('source_switches.Path.read_text',return_value='version=1 owner=1 fd=1\n'):
                with self.assertRaises(ValueError): observe(name)

    def test_missing_fields_are_not_disabled_sources(self):
        with patch('source_switches.Path.read_text',return_value='version=1 owner=0\n'):
            with self.assertRaises(ValueError): observe(None)

    def test_allocator_does_not_enable_counter_or_owner(self):
        with patch('source_switches.Path.read_text', return_value='version=3 owner=0 fd=0 counter=0 allocator=1\n'):
            validate(observe('allocator'),'allocator',0,2**64-1)
            with self.assertRaises(ValueError): observe('counter')
        with patch('source_switches.Path.read_text', return_value='version=2 owner=0 fd=0 counter=0\n'):
            with self.assertRaises(ValueError): observe('allocator')

    def test_release_key_required_and_idle_quiet(self):
        for collector,enabled in (('allocator',1),(None,0)):
            with patch('source_switches.Path.read_text', return_value='version=4 owner=0 fd=0 counter=0 allocator=%d allocator_release=%d\n'%(enabled,enabled)):
                validate(observe(collector),collector,0,2**64-1)
        with patch('source_switches.Path.read_text', return_value='version=4 owner=0 fd=0 counter=0 allocator=0 allocator_release=1\n'):
            with self.assertRaises(ValueError): observe(None)


if __name__=='__main__': unittest.main()
