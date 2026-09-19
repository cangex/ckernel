# SPDX-License-Identifier: GPL-2.0
import unittest
from net_tx_admission_check import check, CASES
from test_net_tx import report_from_episodes


class TxAdmission(unittest.TestCase):
    def fixture(self,case='txadmission'):
        logs=[]; episodes=[]
        for actor in range(2):
            lines=['CIS_SESSION_CONTAINER host_pid=%d'%(actor+101)]
            for phase,n in ((0,16),(1,8)):
                if phase: lines.append('CIS_NET_TX_RESTORED actor=%d time_ns=390'%actor)
                for i in range(n):
                    rejected=case=='txadmission' and not phase and i>=4
                    t=(400 if phase else 100)+i*10
                    r=dict(actor=actor,phase=phase,index=i,cookie=21+actor,begin_ns=t,end_ns=t+5,
                           returned=-1 if rejected else 128,error=11 if rejected else 0)
                    lines.append('CIS_NET_TX_ADMISSION '+' '.join('%s=%s'%p for p in r.items()))
                    episodes.append(dict(requester=[actor+1,1,actor+101,1],cookie=21+actor,begin_ns=t+1,
                        terminal_ns=t+4,backend_interval_ns=[t+1,t+2],skb_address=t*10+actor,
                        outcome='MEMORY_ADMISSION_REJECTED' if rejected else 'ADMITTED',
                        release_entry_ns=t+3 if rejected else 900,packet_payload_owner='UNKNOWN',
                        blocking_container=None,allocator_lock_holder=None))
            logs.append('\n'.join(lines))
        report=dict(quality=dict(status='PASS'),scope_audit=dict(status='PASS'),sockets=[],
                    tx=dict(status='PASS',episodes=episodes,excluded={},unknown={}))
        return [dict(start_ns=50,end_ns=1000),logs,
            dict(time_ns=40,tcp_mem='0 0 0' if case=='txadmission' else '100 200 300',limited=case=='txadmission'),
            dict(time_ns=350,tcp_mem='100 200 300',limited=False),report,[dict(id=1,generation=1),dict(id=2,generation=1)]]

    def test_pressure_and_normal_same_socket_recovery(self):
        for case in CASES:
            args=self.fixture(case)
            self.assertEqual(check(case,*args)['status'],'PASS')
            self.assertEqual(check(case,*args[:4])['status'],'PASS')

    def test_actual_report_schema_and_event_lifetimes(self):
        for case in CASES:
            args=self.fixture(case)
            args[4]=report_from_episodes(args[4]['tx']['episodes'],args[0])
            self.assertEqual(args[4]['quality']['status'],'PASS',args[4])
            self.assertEqual(check(case,*args)['status'],'PASS',args[4])

    def test_rejected_header_must_be_freed_before_terminal(self):
        for change in (dict(release_entry_ns=None),dict(release_entry_ns=900),dict(outcome='BACKEND_ALLOCATION_FAILED'),
                       dict(skb_address=0),dict(blocking_container=2),dict(requester=[2,1,101,1])):
            args=self.fixture();args[4]['tx']['episodes'][4].update(change)
            self.assertEqual(check('txadmission',*args)['status'],'FAIL',change)

    def test_cannot_infer_pressure_from_success_only_or_report_gap(self):
        normal=self.fixture('txnormal');normal[2].update(limited=True,tcp_mem='0 0 0')
        self.assertEqual(check('txadmission',*normal)['status'],'FAIL')
        for change in ('missing','gap','release','relationship'):
            args=self.fixture();report=args[4]
            if change=='missing': report['tx']['episodes'].pop()
            if change=='gap': report['quality']['status']='FAIL'
            if change=='release': report['tx']['episodes'][16]['release_entry_ns']=None
            if change=='relationship': report['sockets']=[dict(waits=[dict(holder=2)])]
            self.assertEqual(check('txadmission',*args)['status'],'FAIL',change)

    def test_restore_barrier_cannot_be_invented_after_recovery(self):
        args=self.fixture(); args[3]['time_ns']=410
        self.assertEqual(check('txadmission',*args)['status'],'FAIL')
        args=self.fixture(); args[3]['limited']=True
        self.assertEqual(check('txadmission',*args)['status'],'FAIL')
        args=self.fixture(); args[3]['tcp_mem']='0 0 0'
        self.assertEqual(check('txadmission',*args)['status'],'FAIL')


if __name__=='__main__': unittest.main()
