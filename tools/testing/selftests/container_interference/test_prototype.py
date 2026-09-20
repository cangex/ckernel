# SPDX-License-Identifier: GPL-2.0
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'container_interference'))
import prototype_admission as proto
from periodic_plan import require_acceptance
from explain import explain, markdown
from owner_test import event
import test_periodic_controller
from schedule import Schedule
from explanation_check import check_owner
from diagnosis_plan import recommend


class Prototype(unittest.TestCase):
    def setUp(self):
        self.source={key: 'a'*64 for key in proto.SOURCE_KEYS}
        self.env=dict(boot_id='guest-boot',architecture='aarch64',page_bytes=4096,
                      online_cpus='0-7',memory_bytes=4*2**30,marker=True,machine_model='linux,dummy-virt')
        self.permit=proto.create(self.source,self.env,100)

    def test_not_production_receipt(self):
        self.assertTrue(proto.validate(self.permit,self.source,self.env,101))
        with self.assertRaises(ValueError):require_acceptance(self.permit,self.source)

    def test_wrong_machine_boot_source_and_expiry(self):
        for key,value in [('marker',False),('architecture','x86_64'),('online_cpus','0-255'),('machine_model','host')]:
            with self.assertRaises(PermissionError):proto.validate(self.permit,self.source,dict(self.env,**{key:value}),101)
        with self.assertRaises(ValueError):proto.validate(self.permit,self.source,dict(self.env,boot_id='new'),101)
        with self.assertRaises(ValueError):proto.validate(self.permit,dict(self.source,worker_sha256='b'*64),self.env,101)
        with self.assertRaises(ValueError):proto.validate(self.permit,self.source,self.env,self.permit['expires_ns'])

    def test_capacity_and_contract_cannot_expand(self):
        proto.admit(self.permit,self.source,self.env,101,4,31,2000)
        for roots,sessions,window in [(5,1,2000),(2,32,2000),(2,1,2001)]:
            with self.assertRaises(ValueError):proto.admit(self.permit,self.source,self.env,101,roots,sessions,window)
        changed=copy.deepcopy(self.permit);changed['limits']=dict(changed['limits'],registered_roots=256)
        with self.assertRaises(ValueError):proto.validate(changed,self.source,self.env,101)

    def test_controller_prototype_is_explicit_and_expires(self):
        controller=test_periodic_controller.ControllerTests().controller()
        controller.schedule=Schedule({},lambda:101)
        controller.admission_policy='prototype'
        controller.prototype_permit=self.permit
        controller.manifest=self.source
        controller.prototype_environment=self.env
        controller.prototype_sessions_started=0
        controller.prototype_digest='a'*64
        with patch('session.now',return_value=101):
            result=controller.request(dict(version=1,op='schedule_enable'))
        self.assertEqual(result['performance_certification'],'NOT_ACCEPTED')
        controller.schedule.pause()
        with patch('session.now',return_value=self.permit['expires_ns']):
            with self.assertRaises(ValueError):controller.request(dict(version=1,op='schedule_enable'))
        self.assertFalse(controller.schedule.enabled)

    def test_model_fallback_does_not_clear_kernel_log(self):
        with patch('prototype_admission.Path.is_file',return_value=False), \
             patch('prototype_admission.os.open',return_value=7) as opened, \
             patch('prototype_admission.os.read',return_value=b'6,1,0,-;Machine model: linux,dummy-virt\n'), \
             patch('prototype_admission.os.close'):
            self.assertEqual(proto.machine_model(),'linux,dummy-virt')
            self.assertEqual(opened.call_args.args[0],'/dev/kmsg')


class Explanations(unittest.TestCase):
    def record(self):
        return dict(session_id='7',collector='ip',result='COMPLETE',objects_absent=True,finalized=True,
            receipt=dict(result='COMPLETE',stop_error=0,capture_error=0,dropped=0,errors=0,output_error=0,
                terminal=dict(valid=True,received=1,emitted=1,rejected=0,lost=0,owner_skipped=0)),
            window=dict(start_ns=0,end_ns=100),
            root_identities={'1:1':dict(id=1,generation=1),'2:1':dict(id=2,generation=1)})

    def owner_report(self, events):
        record=self.record();record['collector']='owner'
        record['receipt']['producer_recursion']=dict(required=True,valid=True,skipped=0)
        raw=b'\n'.join(json.dumps(dict(e,session_id='7')).encode() for e in events)
        return explain(record,raw)

    def test_owner_positive_and_counterexamples(self):
        base=[event(1,3,1),event(2,2,2),event(5,4,1),event(6,3,2)]
        self.assertEqual(self.owner_report(base)['finding_count'],1)
        for bad in ([event(1,3,1),event(2,2,2,obj=200),event(5,4,1),event(6,3,2,obj=200)],
                    [event(1,3,1),event(2,2,2,epoch=20),event(5,4,1),event(6,3,2,epoch=20)],
                    [event(1,3,1),event(2,2,2),event(5,4,1),event(101,3,2)],
                    [event(1,3,3),event(2,2,2),event(5,4,3),event(6,3,2)]):
            self.assertEqual(self.owner_report(bad)['finding_count'],0)

    def test_switch_and_preemption_are_explained_not_added(self):
        events=[event(1,3,1),event(2,2,2),event(3,9,1,flags=1),event(4,10,1),
                event(5,4,1),event(6,3,2)]
        report=self.owner_report(events)
        self.assertEqual(report['findings'][0]['holder_offcpu'][0]['ns'],1)
        self.assertIsNone(report['total_interference_ns'])

    def test_human_tid_is_not_packed_tgid_tid(self):
        events=[event(1,3,1,actor_tid=(100<<32)|101),event(2,2,2,actor_tid=(200<<32)|102),
                event(5,4,1,actor_tid=(100<<32)|101),event(6,3,2,actor_tid=(200<<32)|102)]
        text=markdown(self.owner_report(events))
        self.assertIn('`101`',text)
        self.assertIn('`102`',text)
        self.assertNotIn(str((100<<32)|101),text)

    def test_unsupported_or_outside_intervals_stay_unknown(self):
        for detail in ('type=99 sample_time_ns=1 duration_ns=5',
                       'type=4 sample_time_ns=99 duration_ns=5',
                       'type=4 sample_time_ns=1 duration_ns=-1'):
            report=explain(self.record(),json.dumps(dict(session_id='7',kind='E1',id=1,generation=1,detail=detail)).encode())
            self.assertEqual(report['finding_count'],0)

    def test_sched_uses_interval_endpoint_and_known_identity(self):
        record=self.record();record['collector']='sched'
        record['receipt']['producer_recursion']=dict(required=True,valid=True,skipped=0)
        for time,duration,expected in [(90,20,[70,90]),(10,20,None)]:
            raw=json.dumps(dict(session_id='7',kind='E1',id=1,generation=1,
                                detail='type=2 sample_time_ns=%s duration_ns=%s'%(time,duration))).encode()
            report=explain(record,raw)
            if expected:self.assertEqual(report['findings'][0]['interval_ns'],expected)
            else:self.assertEqual(report['finding_count'],0)

    def test_hotspot_is_not_owner_or_causality(self):
        record=self.record()
        record['survey']=dict(roots={'1:1':dict(valid=True,status='REFERENCE',top_ip=[dict(symbol='page_counter_try_charge')])})
        report=explain(record,b'{"session_id":"7","kind":"IP"}\n')
        self.assertFalse(report['business_loss_causality'])
        self.assertEqual(report['finding_count'],0)
        self.assertIn('page_counter',markdown(report))

    def test_reject_cross_session_and_invalid_json(self):
        for raw in (b'{"session_id":"8"}',b'bad'):
            with self.assertRaises(ValueError):explain(self.record(),raw)

    def test_bad_quality_does_not_produce_direct_fact(self):
        record=self.record();record['receipt']['terminal']['lost']=1
        raw=json.dumps(dict(session_id='7',kind='E1',id=1,generation=1,detail='type=4 duration_ns=20')).encode()
        report=explain(record,raw)
        self.assertEqual(report['quality']['status'],'FAIL')
        self.assertEqual(report['finding_count'],0)
        self.assertEqual(report['unknown_count'],1)

    def test_empty_does_not_mean_no_interference(self):
        report=explain(self.record(),b'')
        self.assertEqual(len(report['analysis_source_sha256']),5)
        self.assertTrue(all(len(value)==64 for value in report['analysis_source_sha256'].values()))
        self.assertEqual(report['unknown'][0]['reason'],'no_raw_events')
        self.assertIsNone(report['total_interference_ns'])

    def test_quota_fact_does_not_require_ip_minimum(self):
        record=self.record()
        record['survey']=dict(roots={'1:1':dict(valid=False,status='INSUFFICIENT',counters=dict(status='VALID',
            files={'cpu.stat':dict(delta=dict(nr_throttled=3),read_intervals_ns=[[1,2],[10,11]])}))})
        report=explain(record,b'{"session_id":"7","kind":"IP"}\n')
        self.assertEqual(report['findings'][0]['kind'],'cpu_throttling_counter')
        self.assertFalse(report['candidates'][0]['valid'])

    def test_fixture_truth_checks_both_parties_and_epoch(self):
        events=[event(1,3,1),event(2,2,2),event(5,4,1),event(6,3,2)]
        logs=['CIS_TRUTH object=100 host_tid=101 cgroup_id=1 begin_ns=0 acquired_ns=1 released_ns=5\n'
              'CIS_TRUTH object=100 host_tid=102 cgroup_id=2 begin_ns=2 acquired_ns=6 released_ns=7']
        self.assertEqual(check_owner(events,logs)['status'],'PASS')
        self.assertEqual(check_owner(events,[logs[0].replace('host_tid=101','host_tid=999')])['status'],'FAIL')
        self.assertEqual(check_owner(events,logs+['CIS_RESET time_ns=3'])['status'],'FAIL')

    def test_candidates_do_not_start_or_promote_unsupported_locks(self):
        report=dict(session_id='7',quality=dict(status='PASS'),candidates=[dict(target='1:1',valid=True,
                    top_ip=[dict(symbol='native_queued_spin_lock_slowpath')],rates={})])
        self.assertEqual(recommend(report),[])
        self.assertEqual(recommend(report,legacy=True)[0]['collector'],'sync')
        self.assertTrue(recommend(report,legacy=True)[0]['requires_confirmation'])
        report['candidates'][0]['top_ip']=[dict(symbol='lockref_get')]
        self.assertEqual(recommend(report),[])
        self.assertTrue(recommend(report,legacy=True)[0]['requires_confirmation'])
        report['quality']['status']='FAIL'
        self.assertFalse(recommend(report))


if __name__=='__main__':unittest.main()
