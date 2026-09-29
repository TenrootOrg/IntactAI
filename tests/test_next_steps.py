"""Next steps (plan step 5): the investigation's to-do list. A report adds its
"Recommended Next Steps" — only new ones, never unticking one, never bringing back
one the analyst deleted. Old and damaged cases read as an empty list.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_HERE, os.path.join(_ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import store  # noqa: E402

LLM_REPORT = """## Impact
- not a step
## Recommended Next Steps
- **Reset** the `vagrant` password
1. Reimage DESKTOP-16OJFO6
    - a sub-point, not a step
2) Collect memory from DC01
## Timeline of Events
- 2026-09-01 not a step
"""
TEMPLATE_REPORT = """## Recommendations
1. **Contain the host** — isolate DESKTOP-16OJFO6
2. **Rotate credentials** — reset vagrant
"""


class Parse(unittest.TestCase):
    def test_the_model_report(self):
        self.assertEqual(store.report_next_steps(LLM_REPORT),
                         ["Reset the vagrant password", "Reimage DESKTOP-16OJFO6", "Collect memory from DC01"])

    def test_the_template_report(self):
        self.assertEqual(store.report_next_steps(TEMPLATE_REPORT),
                         ["Contain the host — isolate DESKTOP-16OJFO6", "Rotate credentials — reset vagrant"])

    def test_no_section_no_steps(self):
        self.assertEqual(store.report_next_steps("## Executive Summary\n- x"), [])
        self.assertEqual(store.report_next_steps(None), [])


class Case:
    def __init__(self, details):
        self.d = details

    def __enter__(self):
        def mut(cid, field, fn):
            self.d[field] = fn(self.d.get(field) or [])
        self.p = [mock.patch.object(store, "get_case", side_effect=lambda cid: self.d),
                  mock.patch.object(store, "_mutate_list_field", side_effect=mut),
                  mock.patch.object(store, "log_case_event")]
        for p in self.p:
            p.start()
        return self

    def __exit__(self, *a):
        for p in self.p:
            p.stop()


class Sync(unittest.TestCase):
    def test_a_report_adds_only_new_steps_and_never_unticks(self):
        with Case({"next_steps": [{"id": "a", "text": "reimage desktop-16ojfo6", "done": True,
                                   "source": "report"}]}) as c:
            self.assertEqual(store.sync_next_steps("c1", LLM_REPORT), 2)       # one was already there
            self.assertEqual(store.sync_next_steps("c1", LLM_REPORT), 0)       # regenerate: nothing twice
        texts = [(x["text"], x["done"]) for x in c.d["next_steps"]]
        self.assertEqual(texts[0], ("reimage desktop-16ojfo6", True))          # still done
        self.assertEqual(len(texts), 3)

    def test_a_deleted_report_step_does_not_come_back(self):
        with Case({"name": "t"}) as c:
            store.sync_next_steps("c1", LLM_REPORT)
            gone = next(x for x in c.d["next_steps"] if x["text"].startswith("Collect"))
            self.assertEqual(store.delete_next_step("c1", gone["id"]), {"deleted": gone["id"]})
            store.sync_next_steps("c1", LLM_REPORT)
        self.assertNotIn("Collect memory from DC01", [x["text"] for x in c.d["next_steps"]])

    def test_add_tick_edit_delete(self):
        with Case({"name": "t"}) as c:
            item = store.add_next_step("c1", "  Call the customer's IT  ")
            self.assertEqual((item["text"], item["done"], item["source"]), ("Call the customer's IT", False, "analyst"))
            self.assertTrue(store.update_next_step("c1", item["id"], done=True)["done"])
            self.assertEqual(store.update_next_step("c1", item["id"], text="Call IT")["text"], "Call IT")
            self.assertIn("error", store.update_next_step("c1", item["id"], text="  "))
            self.assertIn("error", store.add_next_step("c1", " "))
            store.delete_next_step("c1", item["id"])
            self.assertEqual(c.d["next_steps"], [])
            self.assertEqual(c.d.get("next_steps_dismissed"), None)            # own steps are not remembered
            self.assertIn("error", store.delete_next_step("c1", "nope"))

    def test_old_and_damaged_cases(self):
        self.assertEqual(store.next_steps({"name": "old"}), [])
        self.assertEqual(store.next_steps({"next_steps": "junk"}), [])
        self.assertEqual(store.next_steps({"next_steps": [5, {"id": "x"}, {"id": "y", "text": "ok", "source": "?"}]}),
                         [{"id": "y", "text": "ok", "done": False, "source": "analyst", "added_at": None}])
        with Case({"next_steps": "junk", "next_steps_dismissed": {"x": 1}}) as c:
            self.assertEqual(store.sync_next_steps("c1", LLM_REPORT), 3)       # damaged list: rebuilt, no crash
        self.assertEqual(len(c.d["next_steps"]), 3)


class Page(unittest.TestCase):
    def test_the_box_copes_with_missing_and_bad_data(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        with open(os.path.join(_ROOT, "modules/nginx/html/cases.html"), encoding="utf-8") as fh:
            src = fh.read()
        fn = re.search(r"function nextStepsHtml\(.*?\n\}", src, re.S).group(0)
        js = "const esc=s=>String(s); const window={};\n" + fn + """
console.log(JSON.stringify([
  nextStepsHtml({case_id:'c1'}),
  nextStepsHtml({case_id:'c1', next_steps:'junk'}),
  nextStepsHtml({case_id:'c1', next_steps:[{id:'a',text:'Reimage',done:true,source:'report'},{id:'b',text:'Call IT'},{text:'no id'},null]})]));"""
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as t:
            t.write(js)
        try:
            out = json.loads(subprocess.run([node, t.name], capture_output=True, text=True, check=True).stdout)
        finally:
            os.unlink(t.name)
        self.assertIn("none yet", out[0])
        self.assertIn("none yet", out[1])                       # damaged: empty, no crash
        self.assertIn("1 of 2 done", out[2])
        self.assertIn("line-through", out[2])                    # a done step is struck through
        self.assertIn("from report", out[2])
        self.assertIn("nsToggle('c1','b',this.checked)", out[2])


if __name__ == "__main__":
    unittest.main()
