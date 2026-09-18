# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import subprocess
import tempfile
import unittest


class CaptureBuffer(unittest.TestCase):
    def test_bounded_burst_layout(self):
        root = Path(__file__).resolve().parents[4]
        source = r'''
#include "tools/container_interference/include/cis_capture_profile.h"
int main(void) {
    unsigned int cpu, profile;
    if (cis_profile_buffer_pages(8, 8) != 128 || cis_profile_buffer_pages(7, 8) != 16) return 1;
    if (cis_profile_buffer_pages(8, 0) || cis_profile_buffer_pages(8, 513)) return 2;
    for (profile=0; profile<=8; profile++) for (cpu=1; cpu<=512; cpu++) {
        unsigned int p=cis_profile_buffer_pages(profile,cpu);
        if (!p || (p & (p-1)) || (unsigned long long)p*4096*cpu > (4ULL<<20)) return 3;
    }
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            exe=Path(directory)/'check'
            subprocess.run(['cc','-Wall','-Wextra','-Werror','-I',str(root),'-x','c','-o',str(exe),'-'],
                           input=source,text=True,check=True,capture_output=True)
            subprocess.run([str(exe)],check=True)
