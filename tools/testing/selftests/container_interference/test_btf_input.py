# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class BtfInput(unittest.TestCase):
    @unittest.skipUnless(shutil.which('make'), 'make required')
    def test_force_header_generation_never_relinks_prebuilt_kernel(self):
        makefile=Path(__file__).resolve().parents[3]/'container_interference/Makefile'
        with tempfile.TemporaryDirectory() as name:
            p=Path(name); (p/'bpf').mkdir(); kernel=p/'vmlinux'
            kernel.write_bytes(b'PREBUILT IMMUTABLE ELF')
            (p/'vmlinux.o').write_bytes(b'NO IMPLICIT LINK INPUT')
            tool=p/'btf-tool'; tool.write_text('#!/bin/sh\nprintf "GENERATED_HEADER\\n"\n'); tool.chmod(0o700)
            subprocess.run(['make','-f',str(makefile),'-C',name,'-B','bpf/vmlinux.h',
                'VMLINUX_BTF='+str(kernel),'BPFTOOL='+str(tool),'CC=false'],check=True,capture_output=True)
            self.assertEqual(kernel.read_bytes(),b'PREBUILT IMMUTABLE ELF')
            self.assertEqual((p/'bpf/vmlinux.h').read_text(),'GENERATED_HEADER\n')


if __name__=='__main__': unittest.main()
