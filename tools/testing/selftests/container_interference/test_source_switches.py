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


if __name__=='__main__': unittest.main()
