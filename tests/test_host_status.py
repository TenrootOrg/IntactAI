"""Host status on the Risk tab (plan step 4): the analyst's label for a machine,
and — read-only — whether Velociraptor has it quarantined. Old cases have no
statuses; Velociraptor down or absent shows nothing and never fails.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_HERE, os.path.join(_ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import store  # noqa: E402

A = "asset:endpoint:C.fe04b9546801b4fc"


class Saved(unittest.TestCase):
    def run_it(self, asset, status, case=None):
        case = {"name": "qa"} if case is None else case
        with mock.patch.object(store, "get_case", return_value=case), \
             mock.patch.object(store, "_merge_case_details") as merge, \
             mock.patch.object(store, "log_case_event"), \
             mock.patch.object(store, "fuse_case") as fuse:
            res = store.set_host_status("c1", asset, status)
        fuse.assert_not_called()                                   # a label: no re-fuse
        return res, (merge.call_args.args[1] if merge.called else None)

    def test_set_and_clear(self):
        _, patch = self.run_it(A, "Isolated")
        self.assertEqual(patch, {"host_status": {A: "isolated"}})
        _, patch = self.run_it(A, "", {"host_status": {A: "isolated", "asset:x": "clean"}})
        self.assertEqual(patch, {"host_status": {"asset:x": "clean"}})

    def test_bad_input_saves_nothing(self):
        for asset, status in ((A, "nuked"), ("DESKTOP-1", "clean"), ("", "clean")):
            res, patch = self.run_it(asset, status)
            self.assertIn("error", res)
            self.assertIsNone(patch)

    def test_old_and_damaged_cases(self):
        self.assertEqual(store.host_statuses({"name": "old"}), {})
        self.assertEqual(store.host_statuses({"host_status": "junk"}), {})
        self.assertEqual(store.host_statuses({"host_status": {A: "gone", "asset:y": 5, "asset:z": "clean"}}),
                         {"asset:z": "clean"})
        self.assertEqual(store.host_statuses(None), {})


class VelociraptorIsolation(unittest.TestCase):
    def setUp(self):
        store._VR_ISOLATED.update(at=0.0, ids=set())
        self.addCleanup(store._VR_ISOLATED.update, at=0.0, ids=set())

    def _vr(self, fn):
        mod = types.SimpleNamespace(get_clients_from_snapshot=fn)
        return mock.patch.dict(sys.modules, {"services.velociraptor_service": mod}), \
            mock.patch("services.velociraptor_service", mod, create=True)

    def test_the_quarantine_label_marks_the_client(self):
        calls = []

        def clients(include_offline=False):
            calls.append(include_offline)
            return [{"client_id": "C.fe04b9546801b4fc", "labels": ["Quarantine"]},
                    {"client_id": "C.0000000000000001", "labels": ["servers"]}]
        a, b = self._vr(clients)
        with a, b:
            self.assertEqual(store.velociraptor_isolated(), {"C.fe04b9546801b4fc"})
            store.velociraptor_isolated()
        self.assertEqual(calls, [True])                          # cached: asked once a minute

    def test_velociraptor_down_is_no_badge_not_an_error(self):
        def boom(include_offline=False):
            raise ConnectionError("no route")
        a, b = self._vr(boom)
        with a, b:
            self.assertEqual(store.velociraptor_isolated(), set())


class Page(unittest.TestCase):
    def test_tags_and_selector_cope_with_missing_fields(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        with open(os.path.join(_ROOT, "modules/nginx/html/cases.html"), encoding="utf-8") as fh:
            src = fh.read()
        parts = [re.search(r"const HOST_STATUS_LABEL=\{.*?\};", src).group(0),
                 re.search(r"function jsa\(s\)\{.*?;\}", src, re.S).group(0)] + \
                [re.search(r"function %s\(.*?\n\}" % n, src, re.S).group(0) for n in ("_hostStatusTags", "_hostStatusSelect")]
        js = "const esc=s=>String(s);\n" + "\n".join(parts) + """
console.log(JSON.stringify([
  _hostStatusTags({host:'H'}),
  _hostStatusTags({host_status:'isolated', vr_isolated:true}),
  _hostStatusTags({host_status:'bogus'}),
  _hostStatusSelect({client_id:'asset:endpoint:C.1', host_status:'clean'}),
  _hostStatusSelect({client_id:'asset:endpoint:C.1'})]));"""
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as t:
            t.write(js)
        try:
            out = json.loads(subprocess.run([node, t.name], capture_output=True, text=True, check=True).stdout)
        finally:
            os.unlink(t.name)
        self.assertEqual(out[0], "")                                    # old case: nothing shown
        self.assertIn(">Quarantined<", out[1])                          # Velociraptor's word
        self.assertIn("Quarantine (Velociraptor)", out[1])
        self.assertEqual(out[2], "")                                    # damaged: nothing, no crash
        self.assertIn('<option value="clean" selected>', out[3])
        self.assertIn('<option value="" selected>Not set', out[4])
        self.assertIn("event.stopPropagation()", out[4])               # choosing never collapses the row


if __name__ == "__main__":
    unittest.main()
