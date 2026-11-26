"""One case, one sketch (2026-11-24).

Every timeline of a case goes into the Timesketch sketch named after the case:
the import finds it by name or creates it, and a case rename renames it. A case's
runs then share one sketch, so Case Analysis must read only each run's own
timelines, or every run pulls the whole case under its own first host.
"""
import os
import re
import sys
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BACKEND = os.path.join(ROOT, "modules/backend")
for _p in (HERE, BACKEND):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402


def _src(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


class FakeSearch:
    """Mirrors timesketch_api_client.search.Search's indices setter: unknown
    timeline ids leave the search on "_all"."""
    known = {11, 12}

    def __init__(self, sketch):
        self.indices, self.query = "_all", None

    def from_manual(self, query_string=None, max_entries=None):
        self.query = query_string

    def __setattr__(self, k, v):
        if k == "indices" and isinstance(v, list):
            ok = [str(i) for i in v if i in FakeSearch.known]
            if not ok:
                return
            v = ok
        object.__setattr__(self, k, v)

    def to_dict(self):
        return {"objects": [{"_source": {"message": "hit", "indices": self.indices}}]}


def _ts_service():
    search_mod = types.ModuleType("timesketch_api_client.search")
    search_mod.Search = FakeSearch
    pkg = sys.modules.setdefault("timesketch_api_client", types.ModuleType("timesketch_api_client"))
    pkg.search = search_mod
    sys.modules["timesketch_api_client.search"] = search_mod
    from services import timesketch_service
    return timesketch_service


class FakeApi:
    def __init__(self, sketches):
        self._sketches = [types.SimpleNamespace(id=i, name=n) for i, n in sketches]
        self.api_root, self.posts = "https://ts/api/v1", []
        self.session = types.SimpleNamespace(post=self._post, close=lambda: None)

    def _post(self, url, json=None):
        self.posts.append((url, json))
        return types.SimpleNamespace(status_code=200)

    def list_sketches(self):
        return self._sketches

    def get_sketch(self, sid):
        return types.SimpleNamespace(id=sid)


class RunReadsOnlyItsTimelines(unittest.TestCase):
    def setUp(self):
        self.ts = _ts_service()
        p = mock.patch.object(self.ts, "_connect_timesketch_api", return_value=FakeApi([]))
        p.start()
        self.addCleanup(p.stop)

    def test_the_search_is_limited_to_the_runs_timelines(self):
        evs = self.ts.fetch_sketch_events(5, {}, timeline_ids=[11])
        self.assertEqual(evs[0]["indices"], ["11"])

    def test_timelines_gone_from_the_sketch_read_nothing_not_the_whole_case(self):
        self.assertEqual(self.ts.fetch_sketch_events(5, {}, timeline_ids=[99]), [])

    def test_a_run_from_before_reads_the_sketch_as_before(self):
        self.assertEqual(self.ts.fetch_sketch_events(5, {})[0]["indices"], "_all")


class CaseRenameRenamesTheSketch(unittest.TestCase):
    def setUp(self):
        self.ts = _ts_service()

    def _rename(self, sketches, old, new):
        api = FakeApi(sketches)
        with mock.patch.object(self.ts, "_connect_timesketch_api", return_value=api):
            return self.ts.rename_sketch(old, new, {}), api.posts

    def test_the_cases_sketch_takes_the_new_name(self):
        ok, posts = self._rename([(7, "Acme IR")], "Acme IR", "Acme IR 2")
        self.assertTrue(ok)
        self.assertEqual(posts, [("https://ts/api/v1/sketches/7/", {"name": "Acme IR 2"})])

    def test_no_sketch_yet_or_the_new_name_taken_changes_nothing(self):
        self.assertEqual(self._rename([(7, "Other")], "Acme IR", "New"), (False, []))
        self.assertEqual(self._rename([(7, "Acme IR"), (8, "New")], "Acme IR", "New"), (False, []))


class CaseNamesTheSketch(unittest.TestCase):
    def test_the_sketch_name_is_the_case_name(self):
        ts = _ts_service()
        store = types.ModuleType("services.fusion.store")
        store.get_case = lambda cid: {"name": " Acme IR "} if cid == "case_1" else {}
        with mock.patch.dict(sys.modules, {"services.fusion.store": store}), \
                mock.patch("services.fusion.store", store, create=True):
            self.assertEqual(ts.case_sketch_name("case_1"), "Acme IR")
            self.assertIsNone(ts.case_sketch_name("case_gone"))
            self.assertIsNone(ts.case_sketch_name(None))

    def test_every_import_path_uses_the_runs_case(self):
        # process_kape_upload is where the page, the upload and the scheduler meet.
        src = _src("modules/backend/services/kape_upload_service.py")
        self.assertIn("case_sketch = case_sketch_name(case_of(run_id))", src)
        self.assertIn("sketch_id = None if case_sketch else settings.get('sketch_id')", src)
        self.assertIn("d['timeline_ids'].append(tid)", src)
        self.assertIn("case_sketch_name(_job_case(job_meta))", _src("modules/backend/services/scheduler/executor.py"))
        self.assertIn("timeline_ids=det.get(\"timeline_ids\")", _src("modules/backend/services/fusion/store.py"))
        # The rename follows in a background thread (then a restricted case's grants).
        self.assertIn("rename_sketch(old_name, new_name, TIMESKETCH_CONFIG)", _src("modules/backend/routes/case_routes.py"))

    def test_the_pages_no_longer_ask_for_a_sketch_name(self):
        ts = _src("modules/nginx/html/partials/timesketch.html")
        self.assertNotRegex(ts, r'id="(sketch-name|ts-upload-sketch)"')
        self.assertEqual(2, ts.count('class="ts-case-sketch"'))
        self.assertNotIn("schedule-sketch-name", _src("modules/nginx/html/index.html"))
        self.assertNotIn("schedule-sketch-name", _src("modules/nginx/html/js/scheduler.js"))
        self.assertNotRegex(_src("modules/nginx/html/js/timesketch.js"), re.escape("getElementById('sketch-name')"))


if __name__ == "__main__":
    unittest.main()
