# SPDX-License-Identifier: GPL-2.0
import json
from pathlib import Path
import tempfile
import time
import unittest
from costs import CompletionWindow


class CostTests(unittest.TestCase):
    def publish(self,path,start,end,code=0):
        (path/'replay-results').mkdir()
        (path/'replay-results'/'result.json').write_text(json.dumps(dict(start_ns=start,end_ns=end)))
        (path/'done.json').write_text(json.dumps(dict(exit_code=code)))

    def test_snapshot_requires_all_completions(self):
        with tempfile.TemporaryDirectory() as root:
            paths=[Path(root)/str(i) for i in range(2)]
            for p in paths:p.mkdir()
            calls=[]
            window=CompletionWindow(paths,lambda:calls.append(time.monotonic_ns()),timeout=.2)
            start=window.start()
            self.publish(paths[0],start+1,time.monotonic_ns())
            self.assertFalse(window.finished.wait(.01));self.assertEqual(len(calls),1)
            self.publish(paths[1],start+1,time.monotonic_ns())
            result=window.finish_before_grading()
            self.assertEqual(len(calls),2)
            self.assertGreaterEqual(result['end_snapshot_begin_ns'],result['completion_ack_ns'])

    def test_missing_event_refused(self):
        with tempfile.TemporaryDirectory() as root:
            w=CompletionWindow([Path(root)],lambda:{},timeout=.01);w.start()
            with self.assertRaises(TimeoutError):w.finish_before_grading()

    def test_failed_or_early_business_refused(self):
        for code in (0,1):
            with tempfile.TemporaryDirectory() as root:
                p=Path(root);w=CompletionWindow([p],lambda:{},timeout=.1);w.start()
                self.publish(p,0,time.monotonic_ns(),code)
                with self.assertRaises(RuntimeError):w.finish_before_grading()
