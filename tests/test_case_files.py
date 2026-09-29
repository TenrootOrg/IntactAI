"""Case files (plan step 6): attached screenshots / e-mails / logs, each with its
SHA-256. "Include in AI" is off by default; a picture reaches the model by name +
description only, a text file by its text (capped). Old cases have none.
"""
import hashlib
import io
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
from services.fusion import case_files, llm_sim, store  # noqa: E402
from services.fusion.schema import FusionGraph  # noqa: E402


class Files(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.d = {"name": "qa"}

        def mut(cid, field, fn):
            self.d[field] = fn(self.d.get(field) or [])
        for t, a, v in ((case_files, "DATA_DIR", self.tmp), (store, "get_case", lambda cid: self.d),
                        (store, "_mutate_list_field", mut), (store, "log_case_event", mock.Mock())):
            p = mock.patch.object(t, a, v)
            p.start()
            self.addCleanup(p.stop)

    def add(self, name, data):
        return case_files.add("c1", io.BytesIO(data), name)

    def test_upload_records_hash_size_and_kind(self):
        item = self.add("anydesk-silent-install.PNG", b"\x89PNG....")
        self.assertEqual((item["size"], item["kind"], item["ai"]), (8, "image", False))   # AI off by default
        self.assertEqual(item["sha256"], hashlib.sha256(b"\x89PNG....").hexdigest())
        with open(case_files.path_of("c1", item["id"]), "rb") as fh:
            self.assertEqual(fh.read(), b"\x89PNG....")
        self.assertEqual(self.add("mail.eml", b"From: x")["kind"], "text")
        self.assertEqual(self.add("dump.bin", b"\x00\x01")["kind"], "other")

    def test_empty_and_too_big_are_refused(self):
        self.assertIn("empty", self.add("a.txt", b"")["error"])
        with mock.patch.object(case_files, "MAX_BYTES", 4):
            self.assertIn("larger", self.add("a.txt", b"12345")["error"])
        self.assertEqual(os.listdir(os.path.join(self.tmp, "c1")), [])          # no leftovers
        self.assertEqual(case_files.listing(self.d), [])

    def test_rename_describe_flag_delete(self):
        item = self.add("IMG_1234.png", b"x")
        up = case_files.update("c1", item["id"], name="lsass-dump-alert.png", description="Defender alert", ai=True)
        self.assertEqual((up["name"], up["description"], up["ai"]), ("lsass-dump-alert.png", "Defender alert", True))
        self.assertEqual(case_files.update("c1", item["id"], name="notes.txt")["kind"], "text")   # kind follows the name
        self.assertIn("error", case_files.update("c1", "000000000000", ai=True))
        p = case_files.path_of("c1", item["id"])
        self.assertEqual(case_files.delete("c1", item["id"]), {"deleted": item["id"]})
        self.assertFalse(os.path.exists(p))
        self.assertEqual(case_files.listing(self.d), [])

    def test_ids_cannot_reach_outside_the_case(self):
        for bad in ("../../etc/passwd", "..", "", "ABCDEF123456", "x" * 12):
            self.assertIsNone(case_files.path_of("c1", bad))

    def test_only_flagged_files_reach_the_model(self):
        pic = self.add("anydesk-popup.png", b"img")
        log = self.add("firewall.log", b"line1\nline2")
        off = self.add("secret.txt", b"not for the model")
        case_files.update("c1", pic["id"], description="AnyDesk install prompt", ai=True)
        case_files.update("c1", log["id"], ai=True)
        got = case_files.for_model("c1", self.d)
        self.assertEqual(got, [{"file": "anydesk-popup.png", "type": "image", "description": "AnyDesk install prompt"},
                               {"file": "firewall.log", "type": "text", "text": "line1\nline2"}])
        self.assertNotIn(off["name"], json.dumps(got))
        with mock.patch.object(case_files, "AI_TEXT_CAP", 5):
            self.assertEqual(case_files.for_model("c1", self.d)[1]["text"], "line1…[cut]")

    def test_the_model_context_carries_them(self):
        g = FusionGraph(case_id="c1")
        self.assertNotIn("analyst_attached_files", llm_sim.analyst_context(graph=g))
        g.case_files = [{"file": "a.png", "type": "image"}]
        self.assertEqual(llm_sim.analyst_context(graph=g)["analyst_attached_files"], [{"file": "a.png", "type": "image"}])

    def test_old_and_damaged_cases(self):
        self.assertEqual(case_files.listing({"name": "old"}), [])
        self.assertEqual(case_files.listing({"case_files": "junk"}), [])
        self.assertEqual(case_files.listing({"case_files": [5, {"id": "../x", "name": "a"}, {"id": "0123456789ab"}]}), [])
        self.assertEqual(case_files.for_model("c1", {"case_files": None}), [])


class Page(unittest.TestCase):
    def test_box_warns_on_generic_picture_names_and_copes_with_bad_data(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        with open(os.path.join(_ROOT, "modules/nginx/html/cases.html"), encoding="utf-8") as fh:
            src = fh.read()
        parts = [re.search(r"const _CF_GENERIC=.*?;\n", src).group(0)] + \
                [re.search(r"function %s\(.*?\n\}" % n, src, re.S).group(0) for n in ("caseFilesHtml",)] + \
                [re.search(r"function _cfSize\(.*?\}\n", src).group(0)]
        js = "const esc=s=>String(s); const window={};\n" + "\n".join(parts) + """
const f=(n,k)=>({id:'0123456789ab',name:n,kind:k||'image',size:2048,sha256:'ab'.repeat(32)});
console.log(JSON.stringify([
  caseFilesHtml({case_id:'c1'}),
  caseFilesHtml({case_id:'c1', case_files:'junk'}),
  caseFilesHtml({case_id:'c1', case_files:[f('IMG_1234.png'), f('Screenshot 2026-09-29 101010.png'), f('image.png')]}),
  caseFilesHtml({case_id:'c1', case_files:[f('anydesk-silent-install.png'), f('mail.eml','text')]})]));"""
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as t:
            t.write(js)
        try:
            out = json.loads(subprocess.run([node, t.name], capture_output=True, text=True, check=True).stdout)
        finally:
            os.unlink(t.name)
        self.assertIn("none yet", out[0])
        self.assertIn("none yet", out[1])                              # damaged: empty, no crash
        self.assertEqual(out[2].count("give it a descriptive name"), 3)
        self.assertNotIn("give it a descriptive name", out[3])
        self.assertIn("Give pictures a descriptive name", out[0])      # the hint at the upload
        self.assertIn("2 KB", out[3])
        self.assertIn("SHA-256 abababababab", out[3])
        self.assertNotIn('style="width:auto" checked', out[3])        # Include in AI: off by default


if __name__ == "__main__":
    unittest.main()
