import struct
import unittest
import json
import tempfile
from pathlib import Path
from fs_events import CLOSE_WRITE, OVERFLOW, decode_events, final_go_action

class EventTest(unittest.TestCase):
    def test_action_identity(self):
        name = b'actions.json\0'
        value = struct.pack('iIII', 7, CLOSE_WRITE, 0, len(name)) + name
        self.assertEqual(decode_events(value, {7: 2}), {2})

    def test_loss_rejected(self):
        with self.assertRaises(RuntimeError):
            decode_events(struct.pack('iIII', -1, OVERFLOW, 0, 0), {})

    def test_truncation_rejected(self):
        with self.assertRaises(RuntimeError):
            decode_events(b'123', {})

    def test_bounded_final_record(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'actions.json'
            last = dict(kind='execute_bash', id=13, source_command='go version', executed_command='go version',
                        exit_code=0, expected_exit_code=0, end_ns=99, output='go version go1.17 linux/arm64\n')
            p.write_text(json.dumps([dict(output='X'*200000), last], indent=2))
            self.assertEqual(final_go_action(p)['end_ns'], 99)
            last['id'] = 12
            p.write_text(json.dumps([dict(output='X'*200000), last], indent=2))
            self.assertIsNone(final_go_action(p))

    def test_truncated_final_record(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'actions.json'
            p.write_text('[\n  {\n    "id": 13')
            self.assertIsNone(final_go_action(p))

if __name__ == '__main__':
    unittest.main()
