# SPDX-License-Identifier: GPL-2.0
"""Source contract checks, not kernel execution or concurrency validation."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[4]


class SourceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / 'drivers/ckernel/ckernel_main.c').read_text()
        cls.header = (ROOT / 'include/linux/ckernel.h').read_text()

    def test_unsafe_parameters_cannot_be_enabled(self):
        for name in ('ckernel_apparmor', 'ckernel_acct', 'ckernel_vfs_cache',
                     'ckernel_vfs_ref_cache', 'ckernel_immutable_path_lease',
                     'ckernel_socket_fast', 'ckernel_file_socket_stock'):
            self.assertRegex(self.main, rf'module_param_cb\({name},\s*&ckernel_quarantined_ops,\s*&{name}, 0444\)')
            self.assertNotRegex(self.main, rf'static int {name}\s*=\s*[1-9]')
        self.assertIn('if (requested)\n\t\treturn -EOPNOTSUPP;', self.main)

    def test_mask_zero_cannot_activate_maple_or_signal(self):
        self.assertIn('(feature_mask & CKERNEL_FEATURE_MAPLE)', self.main)
        self.assertIn('(feature_mask & CKERNEL_FEATURE_TASK_SECURITY)', self.main)
        self.assertIn('CKERNEL_FEATURE_TASK_SECURITY\tBIT_ULL(8)', self.header)
        self.assertIn('CKERNEL_FEATURE_MAPLE\t\tBIT_ULL(9)', self.header)

    def test_unsupported_mask_is_error_not_silent_cap(self):
        self.assertIn('if (init_args.feature_mask & ~available_features)\n\t\t\t\treturn -EOPNOTSUPP;', self.main)

    def test_misc_failure_before_maple_enable(self):
        init = self.main.split('static int __init ckernel_init(void)', 1)[1]
        self.assertLess(init.index('if (ret)\n\t\treturn ret;'),
                        init.index('ck_maple_meta_domain_enable();'))

    def test_no_default_memcg_stock(self):
        self.assertIn('static int ckernel_memcg_stock;', self.main)


if __name__ == '__main__':
    unittest.main()
