"""Symbol tables by hand, for air-gapped boxes: an uploaded table lands where
VolWeb's Volatility looks — named by its own metadata, never by the file name.
"""
import json
import lzma
import os
import zipfile
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.memory import symbols  # noqa: E402


class Place(unittest.TestCase):
    """The script that runs inside VolWeb's worker, run here on real ISF files."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.lib = os.path.join(self.d, "symbols")

    def run_place(self, path, kind):
        r = subprocess.run([sys.executable, "-c", symbols._PLACE, path, kind, self.lib],
                           capture_output=True, text=True, check=True)
        return json.loads(r.stdout.strip().splitlines()[-1])

    def isf(self, name, meta):
        p = os.path.join(self.d, name)
        doc = {"metadata": {"windows": {"pdb": meta}}, "symbols": {}}
        if name.endswith(".xz"):
            with lzma.open(p, "wt") as fh:
                json.dump(doc, fh)
        else:
            with open(p, "w") as fh:
                json.dump(doc, fh)
        return p

    def test_named_by_its_own_metadata_not_the_upload_name(self):
        p = self.isf("whatever.json.xz", {"GUID": "3844dbb920174967be7aa4a2c20430fa", "age": 2,
                                          "database": "NtKrnlMp.pdb"})
        res = self.run_place(p, "xz")
        self.assertEqual(res["file"], "windows/ntkrnlmp.pdb/3844DBB920174967BE7AA4A2C20430FA-2.json.xz")
        self.assertTrue(os.path.isfile(os.path.join(self.lib, res["file"])))
        self.assertFalse(res["already_had"])

    def test_a_plain_json_is_compressed_and_a_second_copy_is_not_added(self):
        meta = {"GUID": "A1C414A488BC6DE9308B5D3D7579D109", "age": 1, "database": "tcpip.pdb"}
        res = self.run_place(self.isf("t.json", meta), "json")
        with lzma.open(os.path.join(self.lib, res["file"])) as fh:
            self.assertEqual(json.load(fh)["metadata"]["windows"]["pdb"]["database"], "tcpip.pdb")
        again = self.run_place(self.isf("t2.json", meta), "json")
        self.assertTrue(again["already_had"])

    def test_something_that_is_not_a_symbol_table_is_refused(self):
        p = os.path.join(self.d, "bad.json")
        with open(p, "w") as fh:
            fh.write('{"hello": 1}')
        self.assertIn("not a Windows symbol table", self.run_place(p, "json")["error"])


class Add(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def upload(self, name):
        p = os.path.join(self.d, "up.bin")
        with open(p, "wb") as fh:
            fh.write(b"x")
        return p

    def test_only_symbol_files_are_accepted(self):
        self.assertIn("error", symbols.add(self.upload("x"), "notes.txt", dumps_dir=self.d))

    def test_the_staged_copy_is_always_removed(self):
        out = subprocess.CompletedProcess([], 0, stdout='{"file": "windows/ntkrnlmp.pdb/X-1.json.xz"}\n', stderr="")
        with mock.patch.object(symbols, "_exec", return_value=out) as ex:
            res = symbols.add(self.upload("k"), "ntkrnlmp.pdb", dumps_dir=self.d)
        self.assertEqual(res["file"], "windows/ntkrnlmp.pdb/X-1.json.xz")
        self.assertIn(" pdb ", ex.call_args.args[0])                     # converted, not copied
        self.assertEqual(os.listdir(os.path.join(self.d, symbols.INCOMING)), [])

    def zipfile_with(self, names):
        import zipfile
        p = os.path.join(self.d, "pack.zip")
        with zipfile.ZipFile(p, "w") as z:
            for n in names:
                z.writestr(n, b"x")
        return p

    def test_a_pack_goes_in_whole(self):
        ok = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with mock.patch.object(symbols, "_exec", return_value=ok) as ex:
            res = symbols.add(self.zipfile_with(["windows/ntkrnlmp.pdb/X-1.json.xz"]), "windows.zip", dumps_dir=self.d)
        self.assertTrue(res["pack"])
        self.assertIn("cp ", ex.call_args.args[0])

    def test_a_zip_that_is_not_a_symbol_pack_never_reaches_the_library(self):
        # Volatility reads every pack in the library on every run
        with mock.patch.object(symbols, "_exec") as ex:
            self.assertIn("error", symbols.add(self.upload("junk"), "windows.zip", dumps_dir=self.d))
            self.assertIn("no Windows symbol tables",
                          symbols.add(self.zipfile_with(["photos/cat.jpg"]), "photos.zip", dumps_dir=self.d)["error"])
        ex.assert_not_called()



class TheUploadIsLogged(unittest.TestCase):
    """"The upload table upload should be logged in the workflow like the other
    upload in other modules": an 840 MB pack went in and nothing anywhere said so.
    The route (it needs Flask) is lifted out and run with a stub request."""
    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    SRC = open(os.path.join(ROOT, "modules/backend/routes/memory_routes.py"), encoding="utf-8").read()
    FN = re.search(r'@memory_bp.route\("/api/memory/symbols/upload", methods=\["POST"\]\)\n(def upload_memory_symbol\(\):.*?)\n\n\n@memory_bp', SRC, re.S).group(1)

    class _File:
        def __init__(self, name, data=b"x" * 2048):
            self.filename, self._d = name, data

        def save(self, path):
            with open(path, "wb") as fh:
                fh.write(self._d)

    def post(self, file=None, add=None, args=None, enabled=True):
        ev, test = [], self
        runs = {"n": 0}

        query = args if args is not None else {"name": "windows.zip", "size": "880803840"}

        class Req:
            args, content_length = query, 0

            @property
            def files(self):
                ev.append(("body read", runs["n"]))           # how many runs existed when the body was read
                return {"file": file} if file else {}

        def create(**kw):
            runs["n"] += 1
            ev.append(("create", kw["automation_type"], kw["name"]))
            return "run-1"
        ns = {"request": Req(), "jsonify": lambda x: x, "_is_module_enabled": lambda: enabled, "_DUMPS_DIR": "/tmp",
              "create_automation_run": create,
              "add_log_to_run": lambda rid, m, lvl: ev.append(("log", lvl, m)),
              "update_run_status": lambda rid, st, **kw: ev.append(("status", st, kw.get("progress")))}
        with mock.patch.object(symbols, "add", add or (lambda *a, **k: {"file": "t_windows.zip", "pack": True})):
            exec(self.FN, ns)
            out = ns["upload_memory_symbol"]()
        return out, ev

    def test_a_run_is_created_before_the_file_is_read_and_ends_completed(self):
        def add(tmp, name, dumps, log=None):
            log("Symbol pack: 3 Windows symbol table(s) — verifying every file's checksum…")
            return {"file": "t_windows.zip", "pack": True}
        out, ev = self.post(self._File("windows.zip"), add)
        self.assertEqual(ev[0], ("create", "memory_symbols_upload", "Symbol table upload: windows.zip"))
        self.assertEqual([e for e in ev if e[0] == "body read"], [("body read", 1)])    # the run already existed
        logs = [m for k, _, m in [e for e in ev if e[0] == "log"]]
        self.assertEqual(logs[0], "Upload started: windows.zip (840.0 MB)")
        self.assertIn("Upload complete: windows.zip (0.0 MB) received", logs)
        self.assertIn("verifying every file's checksum", " ".join(logs))               # add() narrates into it
        self.assertEqual(logs[-1], "Symbol pack added to the library: t_windows.zip")
        self.assertEqual([e for e in ev if e[0] == "status"][-1], ("status", "completed", 100))
        self.assertEqual(out["run_id"], "run-1")

    def test_a_refused_file_a_missing_file_and_a_crash_all_end_the_run_failed(self):
        cases = ((self._File("x.zip"), lambda *a, **k: {"error": "this .zip holds no Windows symbol tables"}, 400, "no Windows symbol tables"),
                 (None, None, 400, "No file arrived"),
                 (self._File("x.pdb"), mock.Mock(side_effect=RuntimeError("docker gone")), 500, "RuntimeError: docker gone"))
        for file, add, code, words in cases:
            out, ev = self.post(file, add)
            self.assertEqual(out[1], code)
            self.assertIn(words, out[0]["error"])
            self.assertEqual(out[0]["run_id"], "run-1")                                 # the page can point at the log
            self.assertEqual([e for e in ev if e[0] == "status"][-1][1], "failed")      # never left "running"
            self.assertIn(("log", "error", out[0]["error"]), ev)

    def test_a_single_table_says_which_build_can_be_analysed_now(self):
        _, ev = self.post(self._File("ntkrnlmp.pdb"), lambda *a, **k: {"file": "windows/ntkrnlmp.pdb/X-2.json.xz", "already_had": False})
        self.assertIn(("log", "success", "Symbol table added: windows/ntkrnlmp.pdb/X-2.json.xz — images from that "
                                         "Windows build can be analysed now"), ev)
        _, ev = self.post(self._File("ntkrnlmp.pdb"), lambda *a, **k: {"file": "windows/ntkrnlmp.pdb/X-2.json.xz", "already_had": True})
        self.assertIn("nothing changed", [m for k, _, m in [e for e in ev if e[0] == "log"]][-1])

    def test_it_is_a_system_action_and_a_disabled_module_logs_nothing(self):
        ws = open(os.path.join(self.ROOT, "modules/backend/services/workflow_service.py"), encoding="utf-8").read()
        self.assertIn('"memory_symbols_upload"', ws.split("SYSTEM_TYPES = {")[1].split("}")[0])
        out, ev = self.post(self._File("windows.zip"), enabled=False)
        self.assertEqual((out[1], ev), (400, []))
        # THE PAGE uses the same resumable uploader as every other upload, and
        # hands off to Settings → Actions ("look at other upload functions and you
        # understand what i mean"); the plain POST above stays for scripts.
        js = open(os.path.join(self.ROOT, "modules/nginx/html/js/memory.js"), encoding="utf-8").read()
        fn = js[js.index("        uploadSymbol(input) {"):js.index("        async removeDump(d) {")]
        self.assertIn("new TusUploader({", fn)
        self.assertIn("purpose: 'memory_symbols'", fn)
        self.assertIn("systemGuard: false", fn)
        self.assertIn("gotoSystemWorkflows()", fn)
        self.assertNotIn("fetch(", fn)

    def test_add_narrates_its_steps_and_is_silent_without_a_log(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)

        def pack():
            p = os.path.join(d, "up.zip")
            with zipfile.ZipFile(p, "w") as z:
                z.writestr("windows/ntkrnlmp.pdb/X-1.json.xz", b"x")
                z.writestr("windows/tcpip.pdb/Y-1.json.xz", b"x")
            return p
        said = []
        ok = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with mock.patch.object(symbols, "_exec", return_value=ok):
            symbols.add(pack(), "windows.zip", dumps_dir=d, log=said.append)
            symbols.add(pack(), "windows.zip", dumps_dir=d)                            # no log: still works
        self.assertEqual(said, ["Symbol pack: 2 Windows symbol table(s) — verifying every file's checksum…",
                                "Pack verified — checking whether the library already has it…",
                                "Storing the pack in VolWeb's symbol library…"])
        said.clear()
        with mock.patch.object(symbols, "_exec", return_value=subprocess.CompletedProcess([], 0, stdout='{"file": "f"}', stderr="")):
            symbols.add(self._file_on_disk(d, "k.pdb"), "ntkrnlmp.pdb", dumps_dir=d, log=said.append)
        self.assertEqual(said, ["Converting the .pdb to a symbol table with the Volatility inside VolWeb…"])

    def test_the_same_pack_is_not_stored_twice(self):
        # With no feedback during the upload, the 840 MB windows.zip was sent twice
        # and kept twice; Volatility reads every pack in the library on every run.
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        p = os.path.join(d, "up.zip")
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("windows/ntkrnlmp.pdb/X-1.json.xz", b"x")
        digest = symbols._sha256(p)
        calls = []

        def fake_exec(script, timeout=300):
            calls.append(script)
            out = f"{'0' * 64}  other.zip\n{digest}  a1bed8b31c1f_windows.zip\n" if "sha256sum" in script else ""
            return subprocess.CompletedProcess([], 0, stdout=out, stderr="")
        with mock.patch.object(symbols, "_exec", fake_exec):
            res = symbols.add(p, "renamed-copy.zip", dumps_dir=d)
        self.assertEqual(res, {"file": "a1bed8b31c1f_windows.zip", "pack": True, "already_had": True})
        self.assertFalse(any(c.startswith("cp ") for c in calls))            # nothing was copied in
        self.assertFalse(symbols._ADD_LOCK.locked())                         # and the lock was given back
        # one install at a time: two uploads seconds apart each checked before the
        # other had stored anything (live test), and both went in
        body = open(symbols.__file__, encoding="utf-8").read().split("def add(")[1]
        self.assertLess(body.index("_ADD_LOCK.acquire()"), body.index("sha256sum *.zip"))
        self.assertLess(body.index("sha256sum *.zip"), body.index("_ADD_LOCK.release()"))
        self.assertEqual(os.listdir(os.path.join(d, symbols.INCOMING)), [])  # and the staged copy is gone

    @staticmethod
    def _file_on_disk(d, name):
        p = os.path.join(d, name)
        with open(p, "wb") as fh:
            fh.write(b"x")
        return p


class TheSharedUploadHook(unittest.TestCase):
    """tusd's hook (routes/upload_routes.py) for purpose 'memory_symbols': the same
    path as a Velociraptor / Timesketch / memory-image upload."""
    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    SRC = open(os.path.join(ROOT, "modules/backend/routes/upload_routes.py"), encoding="utf-8").read()

    def test_the_purpose_is_accepted_named_and_checked_before_a_byte_is_sent(self):
        pre = self.SRC[self.SRC.index("if event_type == 'pre-create':"):self.SRC.index("elif event_type == 'post-create':")]
        self.assertIn("'memory_symbols']:", pre)
        blk = pre[pre.index("elif purpose == 'memory_symbols':"):][:900]
        self.assertIn("allowed_extensions = ['.zip', '.pdb', '.json.xz', '.json']", blk)
        self.assertIn('"RejectUpload": True', blk)
        post = self.SRC[self.SRC.index("elif event_type == 'post-create':"):self.SRC.index("elif event_type == 'post-receive':")]
        self.assertIn("workflow_type = 'memory_symbols_upload'", post)
        self.assertIn('workflow_name = f"Symbol table upload: {filename}"', post)

    def test_the_install_runs_in_the_background_and_always_ends_the_run(self):
        fin = self.SRC[self.SRC.index("elif event_type == 'post-finish':"):self.SRC.index("elif event_type == 'post-terminate':")]
        blk = fin[fin.index("elif purpose == 'memory_symbols':"):fin.index("elif purpose == 'upgrade_package':")]
        self.assertIn("threading.Thread(target=run_symbol_install, daemon=True).start()", blk)
        self.assertIn("symbols.add(file_path, original_filename,", blk)
        ns, ev = {}, []
        body = re.search(r"(                def run_symbol_install\(\):.*?)\n\n                threading", blk, re.S).group(1)
        import textwrap
        for res, want in (({"file": "t.zip", "pack": True}, ("completed", "Symbol pack added to the library: t.zip")),
                          ({"file": "t.zip", "pack": True, "already_had": True}, ("completed", "nothing changed")),
                          ({"file": "windows/ntkrnlmp.pdb/X-2.json.xz"}, ("completed", "can be analysed now")),
                          ({"error": "this .zip holds no Windows symbol tables"}, ("failed", "no Windows symbol tables")),
                          (RuntimeError("docker gone"), ("failed", "RuntimeError: docker gone"))):
            ev.clear()
            d = tempfile.mkdtemp()
            self.addCleanup(shutil.rmtree, d, ignore_errors=True)
            fp = os.path.join(d, "upl")
            for x in (fp, fp + ".info"):
                open(x, "w").close()
            ns = {"os": os, "file_path": fp, "original_filename": "windows.zip", "run_id": "run-1",
                  "add_log_to_run": lambda rid, m, lvl="info": ev.append(("log", lvl, m)),
                  "update_run_status": lambda rid, st, **kw: ev.append(("status", st))}
            add = mock.Mock(side_effect=res) if isinstance(res, Exception) else mock.Mock(return_value=res)
            with mock.patch.object(symbols, "add", add):
                exec(textwrap.dedent(body), ns)
                ns["run_symbol_install"]()
            self.assertEqual([e for e in ev if e[0] == "status"][-1], ("status", want[0]), res)
            self.assertIn(want[1], ev[-2][2], res)                      # the last log line says what happened
            self.assertEqual(os.listdir(d), [])                         # the uploaded file and its .info are gone


if __name__ == "__main__":
    unittest.main()
