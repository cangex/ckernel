import struct
import unittest
from fs_events import CLOSE_WRITE, OVERFLOW, decode_events

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

if __name__ == '__main__':
    unittest.main()
