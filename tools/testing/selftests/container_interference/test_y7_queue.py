# SPDX-License-Identifier: GPL-2.0
import unittest
from y7_queue_check import workload,captures,validate_plan,validate_namespaces
from y7_private_check import order

class QueueTruth(unittest.TestCase):
    def logs(self):
        client=('Y7_QUEUE_CLIENT actor=0 due=100 begin=101 end=9000000100 offered=4500 completed=4500 errors=0 timeouts=0 period=2000000 timeout=100000000 p99=4455 max=4500 sum=10127250 pidns=10 mntns=20 netns=30\n'
            +'Y7_QUEUE_LATENCIES '+','.join(str(i) for i in range(1,4501))+'\n')
        server='Y7_QUEUE_SERVER actor=0 received=4500 errors=0 duplicates=0 pidns=11 mntns=21 netns=31\n'
        return client,server
    def test_both_endpoints_and_full_arrival_population(self):
        c,s=self.logs();self.assertEqual(workload(c,s,0)['throughput'],500)
        for old,new in [('received=4500','received=4499'),('errors=0','errors=1'),('duplicates=0','duplicates=1'),('actor=0','actor=1')]:
            with self.assertRaises(ValueError):workload(c,s.replace(old,new),0)
        for old,new in [('p99=4455','p99=1'),('completed=4500','completed=4499'),('timeouts=0','timeouts=1')]:
            with self.assertRaises(ValueError):workload(c.replace(old,new),s,0)
        with self.assertRaises(ValueError):workload(c,'',0)

    def test_frozen_sources_and_queue_placement(self):
        self.assertEqual(sum(len(captures(e['mode'])) for e in order()),12)
        self.assertEqual(captures('profile'),('ip','qdisc','cpu'))
        with self.assertRaises(ValueError):captures('net')
        p=dict(schema='cis-y7-queue-plan-v1',arrangement='separate',order=order(),cpus=[0,0,1,1],
            destinations=[0,1,0,1],management_cpu=7,rounds=3,window_ms=2000,offered=4500,
            period_ns=2_000_000,timeout_ns=100_000_000,payload_bytes=1024,egress_rate='100mbit',
            tx_queue=0,selected_ifindex=10)
        validate_plan(p)
        for k,v in [('destinations',[0]*4),('egress_rate','2mbit'),('cpus',[0,1,2,3]),('selected_ifindex',0)]:
            with self.assertRaises(ValueError):validate_plan(dict(p,**{k:v}))

    def test_real_namespace_identity_not_actor_names(self):
        work=[dict(pidns=i+10,mntns=i+20,netns=30,server=dict(pidns=i+40,mntns=i+50,netns=60+i%2)) for i in range(4)]
        plan=dict(destinations=[0,1,0,1]);validate_namespaces(work,plan)
        work[1]['pidns']=10
        with self.assertRaises(ValueError):validate_namespaces(work,plan)
        work[1]['pidns']=11;work[1]['server']['netns']=60
        with self.assertRaises(ValueError):validate_namespaces(work,plan)
