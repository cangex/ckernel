# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import re
import unittest


class FDAdapterSource(unittest.TestCase):
    def test_selected_calls_and_retirement_boundaries(self):
        root=Path(__file__).resolve().parents[4]
        paths={'fs/file.c':40,'fs/legacy-filescontrol.c':6,'fs/misc-filescontrol.c':4,
               'fs/locks.c':4,'fs/proc/fd.c':2,'io_uring/openclose.c':5}
        if not all((root/path).is_file() for path in paths):
            self.skipTest('source audit needs selected kernel files, not a tools-only export')
        for path,count in paths.items():
            text=(root/path).read_text()
            self.assertEqual(len(re.findall(r'\bfiles_(?:lock|unlock)\(',text)),count,path)
            self.assertFalse(re.search(r'\bspin_(?:lock|unlock)\(&\w+->file_lock\)',text),path)
        text=(root/'fs/file.c').read_text()
        self.assertEqual(text.count('cis_files_event(newf, CIS_RESET);'),1)
        for owner in ('newf','files'):
            self.assertRegex(text,r'cis_files_event\('+owner+r', CIS_RETIRE\);\s*kmem_cache_free\(files_cachep, '+owner+r'\);')
        header=(root/'include/linux/fdtable.h').read_text()
        self.assertRegex(header,r'cis_files_event\(files, CIS_WAIT\);\s*spin_lock\(&files->file_lock\);\s*cis_files_event\(files, CIS_ACQUIRE\);')
        self.assertRegex(header,r'cis_files_event\(files, CIS_RELEASE_BEGIN\);\s*spin_unlock\(&files->file_lock\);')


if __name__=='__main__': unittest.main()
