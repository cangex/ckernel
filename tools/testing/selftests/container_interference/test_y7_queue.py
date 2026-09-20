# SPDX-License-Identifier: GPL-2.0
import unittest
from y7_queue_check import workload

class QueueTruth(unittest.TestCase):
    def logs(self):
        client=('Y7_QUEUE_CLIENT actor=0 due=100 begin=101 end=9000000100 offered=4500 completed=4500 errors=0 timeouts=0 period=2000000 timeout=100000000 p99=4455 max=4500 sum=10127250\n'
            +'Y7_QUEUE_LATENCIES '+','.join(str(i) for i in range(1,4501))+'\n')
        server='Y7_QUEUE_SERVER actor=0 received=4500 errors=0 duplicates=0\n'
        return client,server
    def test_both_endpoints_and_full_arrival_population(self):
        c,s=self.logs();self.assertEqual(workload(c,s,0)['throughput'],500)
        for old,new in [('received=4500','received=4499'),('errors=0','errors=1'),('duplicates=0','duplicates=1'),('actor=0','actor=1')]:
            with self.assertRaises(ValueError):workload(c,s.replace(old,new),0)
        for old,new in [('p99=4455','p99=1'),('completed=4500','completed=4499'),('timeouts=0','timeouts=1')]:
            with self.assertRaises(ValueError):workload(c.replace(old,new),s,0)
        with self.assertRaises(ValueError):workload(c,'',0)
