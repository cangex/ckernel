# SPDX-License-Identifier: GPL-2.0
"""Event-acknowledged cost snapshots, independent of official grading.

Polling only discovers published completion events. It never substitutes for
completion, and the snapshot's publication/observation lag remains measurable.
"""
import json
import threading
import time


class CompletionWindow:
    def __init__(self, evidence, snapshot, timeout=180, clock=time.monotonic_ns):
        if not evidence or len(set(map(str,evidence))) != len(evidence):
            raise ValueError('unique nonempty evidence directories required')
        self.evidence=list(evidence);self.snapshot=snapshot;self.timeout=timeout
        self.clock=clock;self.ready=threading.Event();self.finished=threading.Event()
        self.error=None;self.data={};self.thread=None

    def start(self):
        if self.thread is not None:raise RuntimeError('window already started')
        self.data['before_begin_ns']=self.clock()
        self.data['before']=self.snapshot()
        self.data['before_end_ns']=self.clock()
        self.thread=threading.Thread(target=self._collect,daemon=True)
        self.thread.start();self.ready.set()
        return self.data['before_end_ns']

    def _collect(self):
        try:
            deadline=time.monotonic()+self.timeout
            while not all((p/'done.json').is_file() for p in self.evidence):
                if time.monotonic()>=deadline:raise TimeoutError('business completion events missing')
                self.finished.wait(.002)
            events=[]
            for path in self.evidence:
                done=json.loads((path/'done.json').read_text())
                result=json.loads((path/'replay-results'/'result.json').read_text())
                if done.get('exit_code') != 0:raise RuntimeError('business completion failed')
                start=result['start_ns'];end=result['end_ns']
                if type(start) is not int or type(end) is not int or not 0<=start<=end:
                    raise RuntimeError('invalid business clock')
                events.append(dict(start_ns=start,end_ns=end))
            ack=self.clock();last=max(e['end_ns'] for e in events)
            if min(e['start_ns'] for e in events)<self.data['before_end_ns']:
                raise RuntimeError('business began before initial snapshot completed')
            if ack<last:raise RuntimeError('completion clock mismatch')
            self.data.update(events=events,completion_ack_ns=ack,
                             end_snapshot_begin_ns=self.clock())
            self.data['after']=self.snapshot()
            self.data['end_snapshot_end_ns']=self.clock()
            self.data['completion_lag_ns']=self.data['end_snapshot_begin_ns']-last
            self.data['scope']='includes idle/observer/publication lag; not exclusive business CPU attribution'
        except BaseException as exc:self.error=exc
        finally:self.finished.set()

    def finish_before_grading(self):
        if self.thread is None:raise RuntimeError('window not started')
        if not self.finished.wait(self.timeout+1):raise TimeoutError('collector did not acknowledge completion')
        self.thread.join(timeout=1)
        if self.thread.is_alive():raise RuntimeError('collector still active')
        if self.error is not None:raise self.error
        return self.data
