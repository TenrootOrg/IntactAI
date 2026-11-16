"""Velociraptor organization plumbing (services/velo_org.py).

Every Velociraptor query runs in the active case's org (picked when the case is
opened, editable on the case), and
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



class TheCaseDecides(unittest.TestCase):
    """The org is the active case's (chosen when the case is opened), not a
    per-page picker: the request hook, schedules and case bundles follow it."""
    def tearDown(self):
        velo_org.set_current("")

    def _hook(self, headers, cookies, view_args=None):
        import re
        from unittest import mock
        src = open(os.path.join(ROOT, "modules/backend/app.py"), encoding="utf-8").read()
        fn = re.search(r"\ndef _velo_org_from_request\(\):.*?(?=\n\n|\Z)", src, re.S).group(0)
        ns = {"request": mock.Mock(headers=headers, cookies=cookies, view_args=view_args), "velo_org": velo_org}
        from services.fusion import store
        with mock.patch.object(store, "case_velo_org", lambda cid: {"case-acme": "OFM5G"}.get(cid, "")):
            exec(fn, ns)
            ns["_velo_org_from_request"]()
        return velo_org.current()

    def test_the_org_always_comes_from_a_case(self):
        self.assertEqual(self._hook({"X-Case-Id": "case-acme"}, {}), "OFM5G")
        self.assertEqual(self._hook({"X-Case-Id": "case-root"}, {"intact_case": "case-acme"}), "")  # header first
        self.assertEqual(self._hook({"X-Velo-Org": "OTHER"}, {"velo_org": "OTHER"}), "")         # nothing picks an org
        self.assertEqual(self._hook({}, {}), "")

    def test_the_url_case_beats_the_active_one(self):            # /api/cases/<case_id>/...
        self.assertEqual(self._hook({"X-Case-Id": "case-root"}, {}, {"case_id": "case-acme"}), "OFM5G")

    def test_without_the_header_the_cookie_names_the_case(self):  # download links, window.open
        self.assertEqual(self._hook({}, {"intact_case": "case-acme"}), "OFM5G")

    def test_an_org_id_never_walks_out_of_the_datastore(self):
        for bad in ("..", "a..b", ".hidden", "../root"):
            self.assertEqual("", velo_org.clean(bad), bad)
        self.assertEqual("O1.x", velo_org.clean("O1.x"))

    def test_a_schedule_runs_in_its_case_org_now(self):
        from unittest import mock
        from services.fusion import store
        import importlib.util          # the file alone: the package __init__ needs APScheduler
        spec = importlib.util.spec_from_file_location(
            "_sched_executor", os.path.join(ROOT, "modules/backend/services/scheduler/executor.py"))
        executor = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(executor)
        orgs = {"c1": "OFM5G", "default": "DEF01"}
        with mock.patch.object(store, "get_case", lambda cid: {"x": 1} if cid == "c1" else {}), \
                mock.patch.object(store, "ensure_default_case", lambda: "default"), \
                mock.patch.object(store, "case_velo_org", lambda cid: orgs.get(cid, "")):
            self.assertEqual(executor._job_org({"case_id": "c1", "velo_org": "SAVED"}), "OFM5G")
            self.assertEqual(executor._job_org({"case_id": "gone", "velo_org": "SAVED"}), "DEF01")  # like its runs
            self.assertEqual(executor._job_org({"velo_org": "SAVED"}), "SAVED")   # from before case_id existed

    def test_a_case_bundle_does_not_carry_the_source_servers_org(self):
        from services.fusion import case_bundle
        self.assertIn("velo_org", case_bundle._STRIP_FROM_CASE)
        src = open(os.path.join(ROOT, "modules/backend/services/fusion/case_bundle.py"), encoding="utf-8").read()
        self.assertIn('det.pop("velo_org", None)', src)          # its runs lose it on import too

    def test_a_new_case_row_is_made_in_root_not_the_browsers_org(self):
        from unittest import mock
        from services.fusion import store
        seen = []
        ws = mock.Mock(create_automation_run=lambda **kw: seen.append(velo_org.current()) or "case_x")
        with mock.patch.object(store, "_ws", lambda: ws), velo_org.use("OFM5G"):
            store.create_case("org probe")
        self.assertEqual(seen, [""], "create_automation_run stamps the org it runs in on the row")


if __name__ == "__main__":
    unittest.main()
