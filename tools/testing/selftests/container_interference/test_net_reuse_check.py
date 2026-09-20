# SPDX-License-Identifier: GPL-2.0
import unittest
from net_reuse_check import check


class SocketReuse(unittest.TestCase):
    def fixture(self):
        logs=[]; sockets=[]; ids=[dict(id=1,generation=1),dict(id=2,generation=1)]
        for actor in range(2):
            log=['CIS_SESSION_CONTAINER host_pid=%d'%(100+actor)]
            for i in range(8):
                t=100+i*100; cookie=10+actor*8+i; address=200+actor
                log.append('CIS_NET_ORIGIN operation=1 cookie=%d begin_ns=%d end_ns=%d'%(cookie,t,t+10))
                log.append('CIS_NET_REUSE index=%d actor=%d cookie=%d socket=%d created_begin_ns=%d created_end_ns=%d enter_ns=%d acquired_ns=%d release_begin_ns=%d released_ns=%d close_begin_ns=%d close_end_ns=%d'%
                           (i,actor,cookie,address,t,t+11,t+12,t+13,t+14,t+15,t+16,t+20))
                who=[actor+1,1,100+actor,1]
                sockets.append(dict(cookie=cookie,socket_address=address,observed_actors=[who],waits=[],
                    creation_observation=dict(actor=who,evidence='E2',time_ns=t+5),accept_observation=None))
            logs.append('\n'.join(log))
        return [dict(start_ns=0,end_ns=2000),logs,dict(quality=dict(status='PASS'),scope_audit=dict(status='PASS'),excluded={},sockets=sockets),ids]

    def test_actual_close_reuse_and_new_identity(self):
        args=self.fixture(); r=check(*args)
        self.assertEqual(r['status'],'PASS',r)
        self.assertEqual(r['matched'],16)
        self.assertEqual([len(v) for v in r['reused_boundaries']],[7,7])
        self.assertEqual(check(*args[:2])['status'],'PASS')

    def test_unknown_missing_or_redirected_identity_never_passes(self):
        for defect in ('empty','wrong_cookie','actor','old_creation','address','wait','quality','missing'):
            a=self.fixture(); s=a[2]['sockets'][1]
            if defect=='empty': a[2]['sockets']=[]
            if defect=='wrong_cookie': s['cookie']=999
            if defect=='actor': s['observed_actors']=[[2,1,101,1]]
            if defect=='old_creation': s['creation_observation']['time_ns']=105
            if defect=='address': s['socket_address']=999
            if defect=='wait': s['waits']=[dict(observed_holders=[dict(holder=[2,1,101,1])])]
            if defect=='quality': a[2]['quality']['status']='FAIL'
            if defect=='missing': a[1][0]=a[1][0].replace('index=7','index=8')
            self.assertEqual(check(*a)['status'],'FAIL',defect)

    def test_allocator_must_reuse_real_address_not_just_increment_cookie(self):
        a=self.fixture()
        for actor in range(2):
            rows=a[1][actor].splitlines(); number=0
            for i,line in enumerate(rows):
                if line.startswith('CIS_NET_REUSE '):
                    rows[i]=line.replace('socket=%d'%(200+actor),'socket=%d'%(1000+actor*8+number)); number+=1
            a[1][actor]='\n'.join(rows)
        self.assertIn('native_address_reuse_not_exercised',check(*a[:2])['errors'])


if __name__=='__main__': unittest.main()
