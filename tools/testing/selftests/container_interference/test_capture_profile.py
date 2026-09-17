# SPDX-License-Identifier: GPL-2.0
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class CaptureProfileTests(unittest.TestCase):
    def test_native_c_profile_selection(self):
        include = Path(__file__).resolve().parents[3]/'container_interference/include'
        code = r'''
#include <assert.h>
#include "cis_capture_profile.h"
int main(void) {
    assert(cis_profile_program(1, "sample_ip"));
    assert(!cis_profile_program(1, "owner_state"));
    assert(!cis_profile_program(1, "owner_switch"));
    assert(!cis_profile_program(2, "sample_ip"));
    assert(cis_profile_program(2, "owner_state"));
    assert(cis_profile_program(2, "owner_switch"));
    assert(!cis_profile_program(2, "lock_begin"));
    assert(cis_profile_program(0, "lock_begin"));
    assert(cis_profile_map(1, "roots"));
    assert(cis_profile_map(1, "session_window"));
    assert(cis_profile_map(1, "stats"));
    assert(cis_profile_map(1, "events"));
    assert(!cis_profile_map(1, "stacks"));
    assert(!cis_profile_map(1, "watched"));
    assert(!cis_profile_map(2, "work_items"));
    assert(!cis_profile_map(2, "pending"));
    assert(cis_profile_map(2, "stacks"));
    assert(cis_profile_map(2, "targets"));
    assert(cis_profile_map(2, "owner_attempts"));
    assert(cis_profile_map(2, "holder_tasks"));
    assert(cis_profile_map(2, "holders"));
    assert(cis_profile_map(2, "watched"));
    assert(!cis_profile_map(3, "roots"));
    assert(!cis_profile_program(3, "sample_ip"));
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            binary = str(Path(directory)/'profile-test')
            subprocess.run([os.environ.get('CC', 'cc'), '-Wall', '-Wextra', '-Werror',
                            '-I'+str(include), '-x', 'c', '-', '-o', binary], input=code, text=True, check=True)
            subprocess.run([binary], check=True)


if __name__ == '__main__': unittest.main()
