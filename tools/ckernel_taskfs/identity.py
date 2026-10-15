# SPDX-License-Identifier: GPL-2.0
"""Strict identifiers and filesystem identity checks, independent of names."""
import os
from pathlib import Path
import re
import stat
import uuid


def token(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{32}', value):
        raise ValueError('expected canonical 128-bit identity')
    return value


def new_token():
    return uuid.uuid4().hex


def regular(path):
    st = Path(path).lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise RuntimeError('not an exclusive regular file')
    return dict(dev=st.st_dev, ino=st.st_ino, bytes=st.st_size, uid=st.st_uid)


def assert_regular(path, expected):
    if regular(path) != expected:
        raise RuntimeError('backing identity changed')


def device(path):
    st = os.stat(path)
    if not stat.S_ISBLK(st.st_mode):
        raise RuntimeError('not a block device')
    return f'{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}'


def thin_id(value):
    if type(value) is not int or not 0 <= value < 2**24:
        raise ValueError('thin id outside native 24-bit range')
    return value


def canonical_directory(path):
    path = Path(path).absolute()
    if path != path.resolve(strict=True) or not path.is_dir():
        raise RuntimeError('noncanonical control directory')
    st = path.stat()
    if st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise RuntimeError('control directory must be exclusive to current uid')
    return path
