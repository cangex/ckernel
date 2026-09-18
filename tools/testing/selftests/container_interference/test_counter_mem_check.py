# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'container_interference'))
from counter_mem_check import operations


class OperationBoundaries(unittest.TestCase):
    def text(self):
        return '\n'.join('CIS_MEM_OP index=%d begin_ns=%d end_ns=%d bytes=8388608 success=1'%(i,20+i*10,29+i*10) for i in range(16))

    def test_complete_count_not_counter_event_count(self):
        r=operations(self.text(),dict(start_ns=10,end_ns=200))
        self.assertEqual(r['successful_operations'],16)
        self.assertEqual(len(r['operation_wall_ns']),16)
        self.assertEqual(r['complete_loop_span_ns'],159)

    def test_failure_duplicate_and_window_truncation(self):
        for text,window in ((self.text().replace('success=1','success=0',1),dict(start_ns=10,end_ns=200)),
                            (self.text().replace('index=1 ','index=0 ',1),dict(start_ns=10,end_ns=200)),
                            (self.text(),dict(start_ns=10,end_ns=100))):
            with self.assertRaises(ValueError): operations(text,window)


if __name__=='__main__': unittest.main()
