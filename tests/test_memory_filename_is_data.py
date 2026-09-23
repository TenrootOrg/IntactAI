"""An uploaded dump's filename reaches a shell. It must arrive as data.

`POST /api/memory/upload` keeps the operator's filename (basename only, NULs
stripped) and that name travels: it becomes the VolWeb evidence name, and two
`docker exec ... sh -c` commands interpolate it — a `chown`/`stat` when the
image is registered off the shared volume, and, worse, cleanup's `rm -f`.

Both wrapped the path in literal single quotes, which a filename containing a
single quote simply closes. `a'; rm -rf /; '.raw` is a legal filename.

These tests EXECUTE the generated command line through a real `sh` with the
destructive verb swapped for `printf`, and assert the shell sees exactly the
paths intended and nothing ran. Asserting on the string alone would pass any
quoting scheme that merely looks careful.
"""

import ast
import os
import shlex
import subprocess
import tempfile
import typing
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

EVIL = "a'; touch {marker}; '.raw"


def _load(rel, name, extra=None):
    path = os.path.join(ROOT, rel)
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    fn = next(n for n in ast.parse(src).body
              if isinstance(n, ast.FunctionDef) and n.name == name)
    ns = {"os": os, "shlex": shlex, "Callable": typing.Callable, "Any": object}
    ns.update(extra or {})
    exec(compile(ast.get_source_segment(src, fn), path, "exec"), ns)
    return ns[name]


class _FakeRun:
    """Captures the argv a function would have handed to docker."""

    def __init__(self):
        self.cmds = []

    def __call__(self, cmd, **kw):
        self.cmds.append(cmd)
        return type("R", (), {"returncode": 0, "stdout": "1048577", "stderr": ""})


class _ShellBase(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.marker = os.path.join(self.tmp.name, "PWNED")
        self.evil = EVIL.format(marker=self.marker)

    def tearDown(self):
        self.tmp.cleanup()

    def assertContained(self, script, verb, expected_args, also=None):
        """Run the real command line with its destructive verb(s) replaced by
        printf, so what the shell actually parses is what gets checked."""
        safe = script.replace(verb, "printf '%s\\n'", 1)
        if also:
            safe = safe.replace(also, "printf '%s\\n'", 1)
        out = subprocess.run(["sh", "-c", safe], capture_output=True, text=True)
        seen = [l for l in out.stdout.split("\n") if l]
        self.assertEqual(seen, expected_args,
                         "the shell did not see the paths as single arguments")
        self.assertFalse(os.path.exists(self.marker),
                         "the injected command EXECUTED")


class TestCleanupCannotBeTalkedIntoRemovingSomethingElse(_ShellBase):
    """This one is an `rm -f` running as root inside the VolWeb container."""

    def _generate(self, name):
        runner = _FakeRun()
        fn = _load("modules/backend/services/memory/cleanup.py",
                   "_remove_volweb_media_raw",
                   {"_backend_container_name": lambda: "c",
                    "subprocess": type("s", (), {"run": runner,
                                                 "TimeoutExpired": Exception})})
        fn(name, lambda m, level="info": None)
        return runner.cmds[0][-1]

    def test_a_quote_in_the_name_does_not_escape(self):
        self.assertContained(
            self._generate(self.evil), "rm -f",
            [f"/home/app/web/media/evidences/{self.evil}",
             f"/home/app/web/media/staging/{self.evil}"])

    def test_spaces_do_not_split_into_extra_paths(self):
        name = "My Memory Dump.raw"
        self.assertContained(
            self._generate(name), "rm -f",
            [f"/home/app/web/media/evidences/{name}",
             f"/home/app/web/media/staging/{name}"])

    def test_an_ordinary_name_still_works(self):
        name = "DESKTOP-566AT85-F.123.raw"
        self.assertContained(
            self._generate(name), "rm -f",
            [f"/home/app/web/media/evidences/{name}",
             f"/home/app/web/media/staging/{name}"])

    def test_an_empty_name_removes_nothing(self):
        runner = _FakeRun()
        fn = _load("modules/backend/services/memory/cleanup.py",
                   "_remove_volweb_media_raw",
                   {"_backend_container_name": lambda: "c",
                    "subprocess": type("s", (), {"run": runner,
                                                 "TimeoutExpired": Exception})})
        fn("", lambda m, level="info": None)
        self.assertEqual(runner.cmds, [], "an empty name must not reach the shell")


class TestRegisteringAnImageQuotesItsPath(_ShellBase):
    """register_existing_file() chowns and stats the staging path. Since the
    offline path now registers instead of uploading, an operator-supplied
    filename reaches this command for the first time."""

    def _generate(self, name):
        src_path = os.path.join(ROOT, "modules/backend/services/memory/volweb_client.py")
        with open(src_path, encoding="utf-8") as fh:
            src = fh.read()
        # The function is a method; pull its body out of the class.
        tree = ast.parse(src)
        fn = next(n for cls in tree.body if isinstance(cls, ast.ClassDef)
                  for n in cls.body
                  if isinstance(n, ast.FunctionDef) and n.name == "register_existing_file")
        runner = _FakeRun()
        ns = {"os": os, "shlex": shlex, "Any": object, "VolWebError": RuntimeError}
        exec(compile(ast.get_source_segment(src, fn), src_path, "exec"), ns)

        class _Self:
            def _resolve_backend_container(self):
                return "c"

            def _log(self, *a, **k):
                pass

        # The method does its own `import subprocess`, so the real module is
        # the one to patch — and it must be patched, or this test would run a
        # genuine `docker exec` with the hostile filename in it.
        from unittest import mock
        with mock.patch("subprocess.run", runner):
            try:
                ns["register_existing_file"](_Self(), name, case_id=1, os_name="windows")
            except Exception:
                pass                   # it fails later at the Django shell — fine
        self.assertTrue(runner.cmds, "no command was generated")
        return runner.cmds[0][-1]

    # Both verbs are swapped: the path appears twice in one command line
    # (chown then stat), and splitting the line on ';' would cut inside the
    # hostile filename itself.
    def test_a_quote_in_the_name_does_not_escape(self):
        path = f"/home/app/web/media/staging/{self.evil}"
        self.assertContained(self._generate(self.evil), "chown app:app",
                             [path, path], also="stat -c '%s'")

    def test_an_ordinary_name_still_works(self):
        name = "DESKTOP-566AT85-F.123.raw"
        path = f"/home/app/web/media/staging/{name}"
        self.assertContained(self._generate(name), "chown app:app",
                             [path, path], also="stat -c '%s'")

    def test_a_nested_upload_path_survives(self):
        """Uploads register as `_uploads/<id>/<file>` now — a relative path
        with separators must still arrive as one argument."""
        name = "_uploads/abc123/PhysicalMemory.raw"
        path = f"/home/app/web/media/staging/{name}"
        self.assertContained(self._generate(name), "chown app:app",
                             [path, path], also="stat -c '%s'")


if __name__ == "__main__":
    unittest.main(verbosity=2)
