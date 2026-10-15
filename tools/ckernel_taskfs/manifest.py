# SPDX-License-Identifier: GPL-2.0
"""Durable intent journal; deliberately not an atomic transaction with DM."""
import fcntl
import json
import os
from pathlib import Path
import time
from identity import canonical_directory, new_token

FORMAT = 'ckernel-taskfs-v1'


class Store:
    def __init__(self, root, create=False, stamp=None):
        root = Path(root).absolute()
        if create:
            if root.parent != root.parent.resolve(strict=True):
                raise RuntimeError('symlink parent')
            root.mkdir(mode=0o700)
        self.root = canonical_directory(root)
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.identity = (os.fstat(self.fd).st_dev, os.fstat(self.fd).st_ino)
        self.lock = os.open('lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if create:
                self.data = dict(format=FORMAT, owner=new_token(), stamp=stamp,
                    root_identity=list(self.identity), boot=self.boot(), state='NEW',
                    next_id=1, pool=None, templates={}, branches={}, operations=[], pending=None)
                self.save()
            else:
                f = os.open('manifest.json', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.fd)
                with os.fdopen(f) as stream:
                    self.data = json.load(stream)
                if self.data.get('format') != FORMAT or self.data['root_identity'] != list(self.identity):
                    raise RuntimeError('unregistered or replaced directory')
        except BaseException:
            self.close()
            raise

    @staticmethod
    def boot():
        p = Path('/proc/sys/kernel/random/boot_id')
        return p.read_text().strip() if p.exists() else 'LOCAL_UNIT_TEST_ONLY'

    def verify(self):
        path = canonical_directory(self.root)
        st = path.stat()
        if (st.st_dev, st.st_ino) != self.identity:
            raise RuntimeError('control directory replaced')

    def close(self):
        os.close(self.lock)
        os.close(self.fd)

    def save(self):
        self.verify()
        name = 'manifest.' + new_token() + '.tmp'
        fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        with os.fdopen(fd, 'w') as stream:
            json.dump(self.data, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, 'manifest.json', src_dir_fd=self.fd, dst_dir_fd=self.fd)
        os.fsync(self.fd)

    def intent(self, action, identity, detail=None):
        self.verify()
        if self.data['pending'] is not None:
            raise RuntimeError('unreconciled operation; recover before mutation')
        if self.data['boot'] != self.boot():
            raise RuntimeError('boot changed; offline recovery required')
        row = dict(token=new_token(), action=action, identity=identity,
            detail=detail, begin_ns=time.monotonic_ns(), outcome='INTENT')
        self.data['operations'].append(row)
        self.data['pending'] = row['token']
        self.save()
        return row

    def commit(self, row, observed):
        if self.data['pending'] != row['token']:
            raise RuntimeError('intent mismatch')
        row.update(outcome='VERIFIED', end_ns=time.monotonic_ns(), observed=observed)
        self.data['pending'] = None
        self.save()

    def failure(self, row, exc):
        row.update(outcome='RECOVERY_REQUIRED', end_ns=time.monotonic_ns(), error=type(exc).__name__+': '+str(exc))
        self.data['state'] = 'RECOVERY_REQUIRED'
        self.save()
