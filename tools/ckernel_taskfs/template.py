# SPDX-License-Identifier: GPL-2.0
"""Immutable template description, including labels and filesystem tree."""
import hashlib
import os
from pathlib import Path
import stat


def tree_digest(root):
    root=Path(root)
    entries=[]
    for path in [root]+sorted(root.rglob('*')):
        st=path.lstat()
        entry=dict(path=str(path.relative_to(root)),mode=st.st_mode,uid=st.st_uid,gid=st.st_gid)
        if stat.S_ISLNK(st.st_mode):entry['link']=os.readlink(path)
        elif stat.S_ISREG(st.st_mode):
            h=hashlib.sha256()
            with path.open('rb') as f:
                for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
            entry['sha256']=h.hexdigest()
        elif not stat.S_ISDIR(st.st_mode):raise RuntimeError('template special file')
        entry['xattrs']={name:os.getxattr(path,name,follow_symlinks=False).hex()
                         for name in sorted(os.listxattr(path,follow_symlinks=False))}
        entries.append(entry)
    return entries


def validate_spec(spec):
    if set(spec)!= {'bytes','inodes','journal_mib'}:
        raise ValueError('filesystem spec fields')
    if any(type(v) is not int or v<=0 for v in spec.values()):raise ValueError('spec integer')
    if spec['bytes']%4096 or spec['bytes']<256*1024**2 or spec['journal_mib']<16:
        raise ValueError('filesystem geometry')
    if spec['journal_mib']*1024**2>=spec['bytes']//4:
        raise ValueError('journal capacity')
    return dict(spec)


def validate_geometry(fields,spec):
    actual=dict(bytes=int(fields['Block count'])*int(fields['Block size']),
                inodes=int(fields['Inode count']),
                journal_bytes=int(fields['Total journal blocks'])*int(fields['Block size']))
    if actual!=dict(bytes=spec['bytes'],inodes=spec['inodes'],journal_bytes=spec['journal_mib']*1024**2):
        raise RuntimeError('actual ext4 geometry differs from frozen budget')
    return actual
