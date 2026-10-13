"""Bounded inotify observation of existing replay artifacts, not business hooks."""
import ctypes
import os
import select
import struct

CLOSE_WRITE = 0x8
DELETE_SELF = 0x400
MOVE_SELF = 0x800
OVERFLOW = 0x4000
IGNORED = 0x8000

def decode_events(data, watches):
    result = set()
    offset = 0
    while offset < len(data):
        if len(data) - offset < 16:
            raise RuntimeError('short inotify header')
        wd, mask, cookie, length = struct.unpack_from('iIII', data, offset)
        offset += 16
        if len(data) - offset < length:
            raise RuntimeError('short inotify name')
        name = data[offset:offset + length].split(b'\0', 1)[0]
        offset += length
        if mask & (OVERFLOW | DELETE_SELF | MOVE_SELF | IGNORED):
            raise RuntimeError('inotify coverage invalidated')
        if mask & CLOSE_WRITE and name == b'actions.json':
            if wd not in watches:
                raise RuntimeError('unknown action watch')
            result.add(watches[wd])
    return result

class ActionWatch:
    def __init__(self, paths):
        lib = ctypes.CDLL(None, use_errno=True)
        lib.inotify_init1.argtypes = [ctypes.c_int]
        lib.inotify_init1.restype = ctypes.c_int
        lib.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        lib.inotify_add_watch.restype = ctypes.c_int
        self.fd = lib.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), 'inotify_init1')
        self.watches = {}
        try:
            for slot, path in paths.items():
                wd = lib.inotify_add_watch(self.fd, os.fsencode(path.parent), CLOSE_WRITE | DELETE_SELF | MOVE_SELF)
                if wd < 0:
                    raise OSError(ctypes.get_errno(), 'inotify_add_watch')
                if wd in self.watches:
                    raise RuntimeError('two containers unexpectedly share a replay artifact directory')
                self.watches[wd] = slot
        except BaseException:
            self.close()
            raise

    def poll(self, timeout):
        ready, _, _ = select.select([self.fd], [], [], timeout)
        return decode_events(os.read(self.fd, 65536), self.watches) if ready else set()

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1
