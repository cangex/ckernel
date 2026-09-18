# SPDX-License-Identifier: GPL-2.0
import unittest
from net_backlog_check import check_backlog


class Backlog(unittest.TestCase):
    def fixture(self):
        logs=[['CIS_SESSION_CONTAINER host_pid=100'],['CIS_SESSION_CONTAINER host_pid=101']]
        queues=[]
        for i in range(4):
            t=100*i+10
            logs[0].append('CIS_NET_TRUTH index=%d actor=0 cookie=10 socket=20 enter_ns=%d acquired_ns=%d release_begin_ns=%d released_ns=%d hold_ms=30' % (i,t,t+1,t+31,t+35))
            for actor in range(2):
                logs[actor].append('CIS_PACKET_TRUTH index=%d actor=%d cookie=%d begin_ns=%d end_ns=%d bytes=128 valid=1' %
                    (i,actor,10+actor,t+5 if actor else t+36,t+6 if actor else t+38))
            queues.append(dict(skb_address=500+i,queue_epoch_ns=t+6,service_interval_ns=[t+32,t+33],
                service_executor=[1,1,100,1],release_entry_ns=t+37,packet_origin='UNKNOWN',blocking_container=None))
        for actor in range(2):
            logs[actor].append('CIS_PACKET_DRAIN actor=%d cookie=%d begin_ns=400 end_ns=410 bytes=128 valid=1' % (actor,10+actor))
        report=dict(quality=dict(status='PASS'),scope_audit=dict(status='PASS'),excluded={},
            sockets=[dict(cookie=10,socket_address=20,backlog=queues)])
        return dict(start_ns=0,end_ns=500),['\n'.join(s) for s in logs],report,[dict(id=1,generation=1),dict(id=2,generation=1)]

    def test_payload_truth_and_real_queue_service_release(self):
        result=check_backlog(*self.fixture())
        self.assertEqual(result['status'],'PASS',result)
        self.assertEqual(result['captured'],4)

    def test_missing_release_wrong_executor_and_false_blocker_rejected(self):
        for key,value in (('release_entry_ns',None),('service_executor',[2,1,101,1]),
                          ('blocking_container',[2,1]),('packet_origin','sender'),('queue_epoch_ns',1)):
            window,logs,report,ids=self.fixture()
            report['sockets'][0]['backlog'][0][key]=value
            self.assertEqual(check_backlog(window,logs,report,ids)['status'],'FAIL',key)

    def test_socket_identity_and_invalid_payload_not_rescued(self):
        window,logs,report,ids=self.fixture()
        report['sockets'][0]['cookie']=100
        self.assertEqual(check_backlog(window,logs,report,ids)['status'],'FAIL')
        logs[1]=logs[1].replace('valid=1','valid=0')
        self.assertEqual(check_backlog(window,logs,None,None)['status'],'FAIL')

    def test_late_remote_release_is_not_forced_into_recv_interval(self):
        window,logs,report,ids=self.fixture()
        report['sockets'][0]['backlog'][0]['release_entry_ns']=405
        result=check_backlog(window,logs,report,ids)
        self.assertEqual(result['status'],'PASS',result)
        self.assertGreater(result['matches'][0]['episodes'][0]['release_after_receive_return_ns'],0)
        report['sockets'][0]['backlog'][0]['release_entry_ns']=501
        self.assertEqual(check_backlog(window,logs,report,ids)['status'],'FAIL')
