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
    assert(cis_profile_map(3, "roots"));
    assert(!cis_profile_program(3, "sample_ip"));
    assert(cis_profile_program(3, "sched_wait"));
    assert(!cis_profile_program(3, "reclaim_begin"));
    assert(!cis_profile_map(3, "stacks"));
    assert(!cis_profile_map(3, "pending"));
    assert(cis_profile_map(3, "targets"));
    assert(cis_profile_program(4, "reclaim_begin"));
    assert(cis_profile_program(4, "reclaim_end"));
    assert(cis_profile_program(4, "memcg_begin"));
    assert(cis_profile_program(4, "memcg_end"));
    assert(!cis_profile_program(4, "owner_state"));
    assert(!cis_profile_program(4, "sched_wait"));
    assert(cis_profile_map(4, "pending"));
    assert(cis_profile_map(4, "stacks"));
    assert(!cis_profile_map(4, "work_items"));
    assert(!cis_profile_map(4, "watched"));
    assert(cis_profile_program(5, "lock_begin"));
    assert(cis_profile_program(5, "lock_end"));
    assert(!cis_profile_program(5, "owner_state"));
    assert(cis_profile_map(5, "roots"));
    assert(!cis_profile_map(5, "holders"));
    assert(cis_profile_map(6, "roots"));
    assert(cis_profile_map(6, "holders"));
    assert(cis_profile_program(6, "owner_state"));
    assert(cis_profile_program(6, "owner_switch"));
    assert(!cis_profile_program(6, "lock_begin"));
    assert(!cis_profile_map(6, "pending"));
    assert(cis_profile_program(7, "counter_step"));
    assert(!cis_profile_program(7, "owner_state"));
    assert(cis_profile_map(7, "roots"));
    assert(cis_profile_map(7, "pending"));
    assert(!cis_profile_map(7, "holders"));
    assert(cis_profile_program(8, "alloc_step"));
    assert(cis_profile_program(8, "alloc_release"));
    assert(!cis_profile_program(7, "alloc_release"));
    assert(cis_profile_map(8, "alloc_live"));
    assert(!cis_profile_map(7, "alloc_live"));
    assert(!cis_profile_program(8, "counter_step"));
    assert(cis_profile_map(8, "roots"));
    assert(cis_profile_map(8, "pending"));
    assert(!cis_profile_map(8, "holders"));
    assert(cis_profile_map(9, "roots"));
    assert(cis_profile_map(9, "net_watched"));
    assert(cis_profile_map(9, "net_skb"));
    assert(cis_profile_map(9, "net_service"));
    assert(!cis_profile_map(9, "alloc_live"));
    assert(!cis_profile_map(9, "holders"));
    assert(cis_profile_program(9, "net_state"));
    assert(cis_profile_program(9, "net_release"));
    assert(!cis_profile_program(9, "alloc_release"));
    assert(cis_profile_map(10, "roots"));
    assert(cis_profile_map(10, "block_watched"));
    assert(!cis_profile_map(10, "net_watched"));
    assert(!cis_profile_map(10, "holders"));
    assert(cis_profile_program(10, "block_start"));
    assert(cis_profile_program(10, "block_complete"));
    assert(cis_profile_program(10, "block_merge"));
    assert(!cis_profile_program(10, "net_state"));
    assert(cis_profile_map(11, "roots"));
    assert(cis_profile_map(11, "rwsem_watched"));
    assert(cis_profile_map(11, "rwsem_selected"));
    assert(!cis_profile_map(10, "rwsem_selected"));
    assert(cis_profile_program(11, "rwsem_state"));
    assert(!cis_profile_program(11, "owner_state"));
    assert(!cis_profile_map(11, "holders"));
    assert(!cis_profile_map(12, "roots"));
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            binary = str(Path(directory)/'profile-test')
            subprocess.run([os.environ.get('CC', 'cc'), '-Wall', '-Wextra', '-Werror',
                            '-I'+str(include), '-x', 'c', '-', '-o', binary], input=code, text=True, check=True)
            subprocess.run([binary], check=True)


if __name__ == '__main__': unittest.main()
