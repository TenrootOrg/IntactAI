"""Every tests/test_*.py must run its tests when executed directly.

run_tests.sh runs each file as `python3 <file>`. A file without a __main__ block
defines its TestCases and exits 0 -- a green suite that ran nothing. Ten suites
sat like that, and test_fetch_scope.py had 8 of its 18 tests broken unseen.
"""
import glob
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


class EverySuiteRuns(unittest.TestCase):
    def test_every_suite_has_a_main_block(self):
        silent = [os.path.basename(p) for p in sorted(glob.glob(os.path.join(HERE, "test_*.py")))
                  if "__main__" not in open(p, encoding="utf-8").read()]
        self.assertEqual([], silent, "add `if __name__ == \"__main__\": unittest.main()`")


if __name__ == "__main__":
    unittest.main()
