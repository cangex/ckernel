import unittest
from run_w3_fs import check_fsck

class FsckTests(unittest.TestCase):
    def test_clean(self):
        check_fsck(['e2fsck','-f','-n'],0,'Pass 5: Checking group summary information')
    def test_zero_exit_warning_rejected(self):
        with self.assertRaises(AssertionError):
            check_fsck(['e2fsck','-f','-n'],0,'Free blocks count wrong. Fix? no')
    def test_readonly_repair_not_pass(self):
        with self.assertRaises(AssertionError):
            check_fsck(['e2fsck','-f','-n'],1,'')
    def test_replay(self):
        check_fsck(['e2fsck','-E','journal_only','-p'],1,'recovering journal')

if __name__=='__main__':unittest.main()
