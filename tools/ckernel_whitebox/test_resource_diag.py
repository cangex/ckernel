import unittest
from analyze_resource_diag import events,summarize

def event(ns,kind,body='',pid=12,flags='d..1'):
    return dict(ns=ns,kind=kind,body=body,pid=pid,flags=flags,cpu=0)

class TraceTests(unittest.TestCase):
    def test_nested(self):
        xs=[event(1,'slow','lock=0x10'),event(2,'slow','lock=0x20'),event(4,'slow_end'),event(6,'slow_end')]
        s=summarize(xs,{12:0},0,10,{16:'inode',32:'other'},{0:(0,10)})
        self.assertEqual([x['observed_wait_ns'] for x in s['objects']],[5,2])
    def test_fork_exit_reuse(self):
        xs=[event(1,'sched_process_fork','comm=p pid=12 child_comm=c child_pid=13'),
            event(2,'slow','lock=0x10',13),event(3,'slow_end',pid=13),
            event(4,'sched_process_exit',pid=13),event(5,'slow','lock=0x10',13),event(6,'slow_end',pid=13)]
        s=summarize(xs,{12:0},0,10,{16:'inode'},{0:(0,10)})
        self.assertEqual({r['slot'] for r in s['objects']},{0,None})
    def test_irq_not_business_owner(self):
        s=summarize([event(1,'slow','lock=0x10',flags='d.h1'),event(2,'slow_end')],{12:0},0,4,{},{})
        self.assertIsNone(s['objects'][0]['slot'])
    def test_unfinished_not_zero(self):
        s=summarize([event(1,'slow','lock=0x10')],{12:0},0,4,{},{})
        self.assertEqual(s['objects'],[]);self.assertEqual(s['pair_audit']['unfinished_entries'],1)
    def test_decimal_clock(self):
        x=list(events([' x-12 [003] d..1 12.123456789: slow: (abc) lock=0x10']))[0]
        self.assertEqual(x['ns'],12123456789)

if __name__=='__main__':unittest.main()
