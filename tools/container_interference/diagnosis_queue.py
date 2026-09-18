# SPDX-License-Identifier: GPL-2.0
"""Pure bounded specialist queue; execution must use the controller's single slot."""
from collections import Counter,deque
import hashlib
import json

from collector_manifest import COLLECTORS

NS=10**9
LIMITS=dict(capacity=8,ttl_ns=300*NS,cooldown_ns=180*NS,automatic_per_permit=2)


class DiagnosisQueue:
    def __init__(self,clock,ledger=None):
        self.clock=clock; self.items={}; self.enabled=False; self.skipped=Counter(); self.recent=deque(maxlen=32)
        self.last={}; self.auto_started=0; self.last_specialist=False
        if ledger:
            self.auto_started=ledger.get('auto_started',0); self.last=ledger.get('last',{})
            if (type(self.auto_started) is not int or not 0<=self.auto_started<=LIMITS['automatic_per_permit'] or
                    not isinstance(self.last,dict) or len(self.last)>2304 or
                    any(not isinstance(k,str) or len(k)>80 or type(v) is not int or v<0 for k,v in self.last.items())):
                raise ValueError('invalid specialist ledger')
            self.last_specialist=bool(ledger.get('last_specialist',False))

    def ledger(self):
        return dict(auto_started=self.auto_started,last=dict(self.last),last_specialist=self.last_specialist)

    def prune(self,roots,epoch):
        now=self.clock()
        for key,item in list(self.items.items()):
            reason=('unregistered' if item['target'] not in roots else 'epoch_changed' if item['source_epoch']!=epoch
                    else 'expired' if now>=item['expires_ns'] else None)
            if reason: self.items.pop(key); self.skipped[reason]+=1

    def offer(self,proposal,roots,epoch):
        self.prune(roots,epoch); now=self.clock(); p=dict(proposal)
        if (p.get('target') not in roots or p.get('collector') not in COLLECTORS or p['collector']=='ip'
                or p.get('source_epoch')!=epoch or type(p.get('source_end_ns')) is not int
                or not 0<=p['source_end_ns']<=now or now-p['source_end_ns']>=LIMITS['ttl_ns']
                or not isinstance(p.get('source_session'),str) or not p['source_session'].isascii()
                or not p['source_session'].isdigit() or len(p['source_session'])>24):
            raise ValueError('untrusted or stale diagnosis proposal')
        if any((i['target'],i['collector'])==(p['target'],p['collector']) for i in self.items.values()):
            self.skipped['duplicate_pending']+=1; return None
        if len(self.items)>=LIMITS['capacity']: self.skipped['queue_full']+=1; return None
        key=hashlib.sha256(json.dumps([p['target'],p['collector'],p['source_session'],epoch]).encode()).hexdigest()[:24]
        p.update(candidate_id=key,enqueued_ns=now,expires_ns=p['source_end_ns']+LIMITS['ttl_ns'])
        self.items[key]=p; return key

    def select(self,roots,epoch,ready,*,automatic=False,candidate_id=None):
        self.prune(roots,epoch); now=self.clock()
        if automatic and (not self.enabled or self.auto_started>=LIMITS['automatic_per_permit'] or self.last_specialist):
            return None
        candidates=list(self.items.values()) if candidate_id is None else [self.items[candidate_id]]
        eligible=[i for i in candidates if i['collector'] in ready and (not automatic or i.get('automatic_eligible') is True) and
                  now-self.last.get(i['target']+'|'+i['collector'],-LIMITS['cooldown_ns'])>=LIMITS['cooldown_ns']]
        if not eligible: return None
        item=min(eligible,key=lambda i:(min((v for k,v in self.last.items() if k.startswith(i['target']+'|')),default=-1),
                                       i['enqueued_ns'],i['candidate_id']))
        return dict(item,queue_wait_ns=now-item['enqueued_ns'],sample_age_ns=now-item['source_end_ns'],automatic=automatic)

    def admitted(self,item):
        saved=self.items.pop(item['candidate_id'])
        self.last[saved['target']+'|'+saved['collector']]=self.clock()
        if item['automatic']: self.auto_started+=1
        self.last_specialist=True
        self.recent.append(dict(candidate_id=item['candidate_id'],target=item['target'],collector=item['collector'],
            admitted_ns=self.clock(),queue_wait_ns=item['queue_wait_ns'],sample_age_ns=item['sample_age_ns'],automatic=item['automatic']))

    def ordinary_admitted(self):
        self.last_specialist=False

    def status(self,roots,epoch,ready):
        self.prune(roots,epoch)
        return dict(enabled=self.enabled,limits=dict(LIMITS),auto_started=self.auto_started,
            items=[dict(v,collector_previously_validated=v['collector'] in ready) for v in self.items.values()],
            skipped=dict(self.skipped),recent=list(self.recent)[-8:],ordinary_slot_required=self.last_specialist,
            restart_policy='paused; candidates discarded; admission and cooldown ledger retained')
