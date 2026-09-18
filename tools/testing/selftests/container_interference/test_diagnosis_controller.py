# SPDX-License-Identifier: GPL-2.0
from unittest.mock import Mock,patch
import unittest
import test_periodic_controller
import test_prototype
from diagnosis_queue import DiagnosisQueue,NS
from schedule import Schedule
import session


class DiagnosisController(unittest.TestCase):
    def controller(self):
        c=test_periodic_controller.ControllerTests().controller()
        c.nonce_epoch='a'*32
        c.schedule=Schedule(dict(jitter_ms=0),lambda:100*NS)
        c.roots={'1:1':dict(id=1,generation=1,fd=123,path='/sys/fs/cgroup/test')}
        c.schedule.add('1:1'); c.diagnoses=DiagnosisQueue(lambda:100*NS)
        return c

    def item(self,c):
        key=c.diagnoses.offer(dict(target='1:1',collector='counter',source_epoch=0,source_session='7',
            source_end_ns=99*NS,automatic_eligible=True),c.roots,0)
        return key

    def test_queue_cannot_bypass_host_interval(self):
        c=self.controller(); key=self.item(c); c.diagnosis_ready=Mock(return_value={'counter'})
        c.schedule.last_admit_ns=99*NS; c.retire_history=c.storage_admit=Mock(); c.args=Mock(test_faults=False)
        c.children.spawn=Mock()
        with patch('session.os.readlink',return_value='/sys/fs/cgroup/test'):
            with self.assertRaisesRegex(ValueError,'host interval budget'):
                c.request(dict(version=1,op='diagnosis_run',candidate_id=key))
        self.assertIn(key,c.diagnoses.items); self.assertEqual(c.diagnoses.auto_started,0)
        c.children.spawn.assert_not_called()

    def test_queue_uses_same_start_and_records_provenance(self):
        c=self.controller(); key=self.item(c); c.diagnosis_ready=Mock(return_value={'counter'})
        c.start=Mock(return_value=dict(session_id='9'))
        r=c.request(dict(version=1,op='diagnosis_run',candidate_id=key))
        request=c.start.call_args.args[0]; planned=c.start.call_args.kwargs['planned']
        self.assertEqual(r['session_id'],'9'); self.assertEqual(request['collector'],'counter')
        self.assertEqual(request['nonce_epoch'],c.nonce_epoch)
        self.assertEqual(planned['kind'],'manual_diagnosis'); self.assertEqual(planned['diagnosis']['sample_age_ns'],NS)

    def test_active_fault_and_strict_do_not_enable_automatic(self):
        c=self.controller(); c.admission=dict(record={})
        with self.assertRaises(OSError): c.request(dict(version=1,op='diagnosis_auto',enabled=True))
        c.admission=None
        with self.assertRaises(ValueError): c.request(dict(version=1,op='diagnosis_auto',enabled=True))
        c.admission_policy='prototype'; c.faulted=True
        with self.assertRaises(ValueError): c.request(dict(version=1,op='diagnosis_auto',enabled=True))
        c.faulted=False; c.request(dict(version=1,op='diagnosis_auto',enabled=True)); self.assertTrue(c.diagnoses.enabled)

    def test_invalid_quality_or_source_does_not_establish_capability(self):
        c=self.controller(); r=test_prototype.Explanations().record(); r['collector']='owner'
        r['receipt']['producer_recursion']=dict(required=True,valid=True,skipped=0)
        c.manifest={k:'frozen' for k in session.prototype_admission.SOURCE_KEYS}
        r.update(c.manifest); c.history={'7':r}
        self.assertEqual(c.diagnosis_ready(),{'owner'})
        r['bpf_sha256']='other'; self.assertFalse(c.diagnosis_ready())
        r['bpf_sha256']='frozen'; r['receipt']['producer_recursion']['skipped']=1
        self.assertFalse(c.diagnosis_ready())

    def test_normal_reference_can_offer_manual_not_automatic(self):
        c=self.controller(); r=test_prototype.Explanations().record(); r['collector']='ip'; r['survey_epoch']=0
        r['window']=dict(start_ns=98*NS,end_ns=99*NS)
        r['survey']=dict(roots={'1:1':dict(valid=True,candidate=False,top_ip=[dict(symbol='page_counter_try_charge')],rates={})})
        self.assertEqual(len(c.diagnosis_offer(r)),1)
        item=next(iter(c.diagnoses.items.values())); self.assertFalse(item['automatic_eligible'])
        r['survey_epoch']=1; self.assertFalse(c.diagnosis_offer(r))
