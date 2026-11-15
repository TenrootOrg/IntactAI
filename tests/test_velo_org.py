"""Velociraptor organization plumbing (services/velo_org.py).

Every Velociraptor query runs in the org the operator picked in the top bar, and
work started in an org keeps it: threads, executor jobs and timers inherit it,
and work that runs later from a stored run re-enters the org saved with it.
"""
import os
import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services import velo_org  # noqa: E402

velo_org.install_thread_inheritance()


class Org(unittest.TestCase):
    def tearDown(self):
        velo_org.set_current("")

    def test_root_and_junk_mean_root(self):
        for v in (None, "", "root", " root ", "a b", "x'; DROP", "o" * 65):
            self.assertEqual("", velo_org.clean(v), v)
        self.assertEqual("OFM5G", velo_org.clean(" OFM5G "))

    def test_use_restores_the_previous_org(self):
        velo_org.set_current("A")
        with velo_org.use("B"):
            self.assertEqual("B", velo_org.current())
            with velo_org.root():
                self.assertEqual("", velo_org.current())
        self.assertEqual("A", velo_org.current())

    def test_threads_timers_and_pool_jobs_inherit_the_org(self):
        seen = {}
        velo_org.set_current("OFM5G")
        t = threading.Thread(target=lambda: seen.__setitem__("thread", velo_org.current()))
        t.start(); t.join()
        tm = threading.Timer(0, lambda: seen.__setitem__("timer", velo_org.current()))
        tm.start(); tm.join()
        with ThreadPoolExecutor(1) as ex:
            # The pool's worker thread is created by this first submit; the second
            # submit, made in another org, must not run in the first one's.
            seen["pool1"] = ex.submit(velo_org.current).result()
            velo_org.set_current("OTHER")
            seen["pool2"] = ex.submit(velo_org.current).result()
        self.assertEqual({"thread": "OFM5G", "timer": "OFM5G", "pool1": "OFM5G", "pool2": "OTHER"}, seen)

    def test_a_thread_started_in_root_stays_in_root(self):
        seen = []
        velo_org.set_current("")
        t = threading.Thread(target=lambda: seen.append(velo_org.current()))
        t.start(); t.join()
        self.assertEqual([""], seen)

    def test_a_stored_run_names_its_org(self):
        self.assertEqual("OFM5G", velo_org.of_run({"details": {"velo_org": "OFM5G"}}))
        self.assertEqual("OFM5G", velo_org.of_run({"details": '{"velo_org": "OFM5G"}'}))
        self.assertEqual("", velo_org.of_run({"details": {}}))
        self.assertEqual("", velo_org.of_run(None))

    def test_cli_flag_and_datastore_path(self):
        self.assertEqual([], velo_org.cli_args(""))
        self.assertEqual(["--org", "OFM5G"], velo_org.cli_args("OFM5G"))
        self.assertEqual("/var./", velo_org.datastore(""))
        self.assertEqual("/var./orgs/OFM5G/", velo_org.datastore("OFM5G"))

    def test_in_root(self):
        @velo_org.in_root
        def f():
            return velo_org.current()
        velo_org.set_current("OFM5G")
        self.assertEqual("", f())
        self.assertEqual("OFM5G", velo_org.current())


if __name__ == "__main__":
    unittest.main()
