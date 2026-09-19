# SPDX-License-Identifier: GPL-2.0
import copy
import unittest
from net_tx_failure_check import check, CASES


class TxFailure(unittest.TestCase):
    def fixture(self, case='txfailure'):
        logs=[]; episodes=[]
        for actor in range(2):
            lines=['CIS_SESSION_CONTAINER host_pid=%d' % (actor+101)]
            for i in range(8):
                armed=int(i%2==0 and (actor==0 or case=='txfailure')); start=100+i*100
                r=dict(index=i,armed=armed,cookie=actor+21,begin_ns=start,end_ns=start+30,
                       returned=-1 if armed else 128,error=11 if armed else 0,received=0 if armed else 128,restored=1)
                lines.append('CIS_NET_TX_FAILURE '+' '.join('%s=%s'%p for p in r.items()))
                episodes.append(dict(requester=[actor+1,1,actor+101,1],cookie=actor+21,begin_ns=start+1,
                    backend_interval_ns=[start+2,start+10],terminal_ns=start+12,
                    outcome='BACKEND_ALLOCATION_FAILED' if armed else 'ADMITTED',
                    skb_address=0 if armed else actor*100+i+1,release_entry_ns=None if armed else start+40,
                    packet_payload_owner='UNKNOWN',blocking_container=None,allocator_lock_holder=None,backend_cpu_ns=None))
            logs.append('\n'.join(lines))
        report=dict(quality=dict(status='PASS'),scope_audit=dict(status='PASS'),relationships=[],
                    tx=dict(status='PASS',episodes=episodes,excluded={},unknown={}))
        return dict(start_ns=50,end_ns=1000),logs,report,[dict(id=1,generation=1),dict(id=2,generation=1)]

    def test_native_truth_both_actors_and_unmarked_control(self):
        for case in CASES:
            args=self.fixture(case)
            self.assertEqual(check(case,*args)['status'],'PASS')
            self.assertEqual(check(case,*args[:2])['status'],'PASS')
            self.assertEqual(sum(p['failed_sends'] for p in check(case,*args)['participants']),
                             8 if case=='txfailure' else 4)

    def test_no_fabricated_success_release_or_blocker(self):
        for changes in (dict(outcome='ADMITTED'),dict(skb_address=1),dict(release_entry_ns=140),
                        dict(blocking_container=2),dict(cookie=22),dict(requester=[2,1,101,1]),
                        dict(terminal_ns=None),dict(begin_ns=99)):
            window,logs,report,ids=self.fixture(); report['tx']['episodes'][0].update(changes)
            self.assertEqual(check('txfailure',window,logs,report,ids)['status'],'FAIL',changes)

    def test_no_hiding_loss_or_missing_recovery(self):
        window,logs,base,ids=self.fixture()
        for change in ('loss','missing','duplicate','unclosed','relationship'):
            report=copy.deepcopy(base)
            if change=='loss': report['quality']['status']='FAIL'
            if change=='missing': report['tx']['episodes'].pop()
            if change=='duplicate': report['tx']['episodes'].append(copy.deepcopy(report['tx']['episodes'][0]))
            if change=='unclosed': report['tx']['episodes'][1]['release_entry_ns']=None
            if change=='relationship': report['relationships']=[dict(holder=2)]
            self.assertEqual(check('txfailure',window,logs,report,ids)['status'],'FAIL',change)

    def test_actual_return_value_and_task_flag_required(self):
        for old,new in (('restored=1','restored=0'),('error=11','error=12'),
                        ('armed=1','armed=0'),('received=0','received=128')):
            window,logs,report,ids=self.fixture(); logs[0]=logs[0].replace(old,new,1)
            self.assertEqual(check('txfailure',window,logs,report,ids)['status'],'FAIL')


if __name__=='__main__': unittest.main()
