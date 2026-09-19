# SPDX-License-Identifier: GPL-2.0
import unittest
from net_fixture_check import check_case, case_order


class NetFixture(unittest.TestCase):
    def fixture(self, case='shared'):
        logs = []
        sockets = []
        identities = [dict(id=i+1, generation=1) for i in range(2)]
        private=case in ('private','rightsPrivate')
        switching=case in ('switch','rightsShared','rightsPrivate')
        for actor in range(2):
            rows = ['CIS_SESSION_CONTAINER host_pid=%d' % (actor+100)]
            if case.startswith('rights'):
                rows.append('CIS_NET_RIGHTS actor=%d sent_cookie=%d received_cookie=%d used_cookie=%d private=%d'%
                            (actor,0 if actor else 10,10 if actor else 0,10+actor if private else 10,int(private)))
            for i in range(4):
                holder = i % 2 if switching else 0
                start = 100*i+10
                enter = start if actor == holder else start+5
                acquired = start+1 if actor == holder else start+32
                begin = start+31 if actor == holder else start+33
                released = start+32 if actor == holder else start+34
                rows.append('CIS_NET_TRUTH index=%d actor=%d scenario=%s cookie=%d socket=%d enter_ns=%d acquired_ns=%d release_begin_ns=%d released_ns=%d hold_ms=%d' %
                    (i, actor, case, 10+actor if private else 10,
                     20+actor if private else 20, enter, acquired, begin, released, 30 if actor==holder else 0))
            logs.append('\n'.join(rows))
        for i in range(4):
            holder = i % 2 if switching else 0
            waiter = 1-holder
            t = 100*i+10
            sockets.append(dict(cookie=10, socket_address=20, waits=[dict(
                waiter=[waiter+1, 1, waiter+100, 1], interval_ns=[t+6, t+32], observed_holders=[dict(
                    holder=[holder+1, 1, holder+100, 1], holder_acquire_ns=t+1,
                    holder_release_ns=t+31, relation_scope='cross_container')])]))
        report = dict(quality=dict(status='PASS'), scope_audit=dict(status='PASS'), excluded={},
                      sockets=[] if private else sockets)
        return dict(start_ns=0, end_ns=1000), logs, report, identities

    def test_exact_relations_and_private_negative(self):
        for case in ('shared','private','switch'):
            value = check_case(case, *self.fixture(case))
            self.assertEqual(value['status'], 'PASS', value)
            self.assertEqual(value['captured'], 0 if case=='private' else 4)
        self.assertEqual(len(case_order()), 18)

    def test_wrong_owner_lost_and_unobserved_relations_rejected(self):
        for mutation in ('owner','missing','quality','cookie'):
            window, logs, report, ids = self.fixture()
            if mutation=='owner': report['sockets'][0]['waits'][0]['observed_holders'][0]['holder'][0]=7
            if mutation=='missing': report['sockets'].pop()
            if mutation=='quality': report['quality']['status']='FAIL'
            if mutation=='cookie': report['sockets'][0]['cookie']=99
            self.assertEqual(check_case('shared',window,logs,report,ids)['status'],'FAIL')

    def test_private_cannot_claim_other_owner(self):
        window,logs,report,ids=self.fixture('private')
        report['sockets']=self.fixture()[2]['sockets']
        self.assertIn('false_cross_container_relation',check_case('private',window,logs,report,ids)['errors'])

    def test_real_rights_selection_is_required_not_inferred_from_same_function(self):
        for case in ('rightsShared','rightsPrivate'):
            args=self.fixture(case)
            result=check_case(case,*args)
            self.assertEqual(result['status'],'PASS',result)
            self.assertEqual(result['captured'],4 if case=='rightsShared' else 0)
            args[1][1]=args[1][1].replace('received_cookie=10','received_cookie=99')
            self.assertIn('wrong_rights_transfer',check_case(case,*args)['errors'])

    def origin_fixture(self):
        window,logs,report,ids=self.fixture('rightsShared')
        logs[0]+='\nCIS_NET_ORIGIN operation=1 cookie=10 begin_ns=1 end_ns=9'
        waits=[wait for sock in report['sockets'] for wait in sock['waits']]
        report['sockets']=[dict(cookie=10,socket_address=20,waits=waits,creation_owner=[1,1,100,1],
            creation_observation=dict(actor=[1,1,100,1],evidence='E2',time_ns=5),accept_observation=None)]
        return window,logs,report,ids

    def test_origin_truth_is_required_and_transferred_user_not_creator(self):
        args=self.origin_fixture()
        result=check_case('rightsShared',*args,require_origin=True)
        self.assertEqual(result['status'],'PASS',result)
        self.assertEqual(result['origin_captured'],1)
        args[2]['sockets'][0]['creation_observation']['actor']=[2,1,101,1]
        self.assertIn('wrong_origin_actor_or_time',check_case('rightsShared',*args,require_origin=True)['errors'])

    def test_missing_origin_or_truth_not_accepted_as_unknown_success(self):
        args=self.origin_fixture(); args[2]['sockets'][0]['creation_observation']=None
        self.assertIn('origin_not_observed',check_case('rightsShared',*args,require_origin=True)['errors'])
        args=self.origin_fixture(); args[1][0]=args[1][0].split('\nCIS_NET_ORIGIN')[0]
        self.assertIn('origin_truth_shape',check_case('rightsShared',*args,require_origin=True)['errors'])
