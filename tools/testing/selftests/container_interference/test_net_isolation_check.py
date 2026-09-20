# SPDX-License-Identifier: GPL-2.0
import copy
import unittest

from net_isolation_check import namespaces,quota
import test_net_fixture_check


class NetIsolation(unittest.TestCase):
    def fixture(self,case='private'):
        window,logs,report,ids=test_net_fixture_check.NetFixture().fixture(case)
        facts=[]
        for actor in range(2):
            cookie=10+actor if case in ('private','rightsPrivate') else 10
            task=1000+actor
            socket_ns=900 if case=='private' else task if case=='rightsPrivate' else 1000
            logs[actor]+='\nCIS_NET_NAMESPACE actor=%d cookie=%d task_ns=%d socket_ns=%d'%(actor,cookie,task,socket_ns)
            facts.append(dict(cookie=cookie,netns=socket_ns,observed_actors=[[actor+1,1,actor+100,1]]))
        if facts[0]['cookie']==facts[1]['cookie']:
            facts[0]['observed_actors']+=facts[1]['observed_actors']; facts=facts[:1]
        report['sockets']=facts
        return case,logs,report

    def test_namespace_oracle_is_socket_fd_not_current(self):
        for case in ('private','rightsPrivate','rightsShared'):
            args=self.fixture(case)
            self.assertEqual(namespaces(*args)['status'],'PASS')
            self.assertEqual(namespaces(*args[:2])['status'],'PASS')
        args=self.fixture('rightsShared'); args[2]['sockets'][0]['netns']=1001
        self.assertEqual(namespaces(*args)['status'],'FAIL')

    def test_private_cannot_pass_with_no_observation_or_missing_truth(self):
        for defect in ('empty','actor','duplicate','missing','same_task'):
            args=self.fixture()
            if defect=='empty': args[2]['sockets']=[]
            if defect=='actor': args[2]['sockets'][1]['observed_actors']=[]
            if defect=='duplicate': args[2]['sockets'].append(copy.deepcopy(args[2]['sockets'][0]))
            if defect=='missing': args[1][0]=args[1][0].split('\nCIS_NET_NAMESPACE')[0]
            if defect=='same_task': args[1][1]=args[1][1].replace('task_ns=1001','task_ns=1000')
            self.assertEqual(namespaces(*args)['status'],'FAIL',defect)

    def quota_fixture(self):
        logs=['CIS_NET_QUOTA actor=0 begin_ns=100 end_ns=400000100 cpu_begin_ns=1000 cpu_end_ns=80001000 requested_cpu_ns=80000000','']
        before=dict(roots=[dict(**{'cpu.max':c,'cpu.stat':'nr_throttled 0\nthrottled_usec 0\nusage_usec 0\n'})
                           for c in ('20000 100000','max 100000')])
        after=copy.deepcopy(before)
        after['roots'][0]['cpu.stat']='nr_throttled 4\nthrottled_usec 320000\nusage_usec 85000\n'
        return dict(start_ns=0,end_ns=2000000000),logs,before,after

    def test_real_throttle_and_unthrottled_bystander_required(self):
        self.assertEqual(quota(*self.quota_fixture())['status'],'PASS')
        for defect in ('no_throttle','bystander','config','clock','missing','regressed'):
            args=list(self.quota_fixture())
            if defect=='no_throttle': args[3]=copy.deepcopy(args[2])
            if defect=='bystander': args[3]['roots'][1]['cpu.stat']='nr_throttled 1\nthrottled_usec 1\nusage_usec 1\n'
            if defect=='config': args[2]['roots'][0]['cpu.max']='max 100000'
            if defect=='clock': args[1][0]=args[1][0].replace('end_ns=400000100','end_ns=400')
            if defect=='missing': args[1][0]=''
            if defect=='regressed': args[2]['roots'][0]['cpu.stat']='nr_throttled 5\nthrottled_usec 999999\nusage_usec 90000\n'
            self.assertEqual(quota(*args)['status'],'FAIL',defect)


if __name__=='__main__': unittest.main()
