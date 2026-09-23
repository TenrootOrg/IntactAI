"""Re-analysing a memory image the appliance already holds.

Two things have to hold or this feature is worse than useless:

1. The path comes from the browser and ends up being read by the pipeline and
   interpolated into a `docker exec` inside the VolWeb container. It must be
   contained to the dumps volume by RESOLVED path — `..` and a symlink out of
   the volume both defeat a string-prefix test.
2. The image must not be copied. /data/memory_dumps and VolWeb's media/staging
   are one shared volume under two names, so a file already there needs a DB
   row, not a multi-GB HTTP upload that lands a second copy.
"""

import ast
import os
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROUTES = os.path.join(ROOT, "modules/backend/routes/memory_routes.py")
PIPELINE = os.path.join(ROOT, "modules/backend/services/memory/pipeline.py")


def _load(path, name, extra=None):
    """The real function, executed without importing its package (the backend
    needs grpc at import time; this box has none)."""
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    fn = next(n for n in ast.parse(src).body
              if isinstance(n, ast.FunctionDef) and n.name == name)
    ns = {"os": os, "Any": object}
    ns.update(extra or {})
    exec(compile(ast.get_source_segment(src, fn), path, "exec"), ns)
    return ns[name]


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


class TestThePathIsContainedByItsRealLocation(unittest.TestCase):
    """A dump path is operator input. These EXECUTE the guard against a real
    temp filesystem — the escapes that matter are filesystem facts, not string
    facts, so a test over strings would pass code that lets them through."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.join(self.tmp.name, "memory_dumps")
        self.outside = os.path.join(self.tmp.name, "elsewhere")
        os.makedirs(self.root)
        os.makedirs(self.outside)

        self.good = os.path.join(self.root, "HOST-F.123.raw")
        self._write(self.good, 2 * 1024 * 1024)
        self.secret = os.path.join(self.outside, "shadow")
        self._write(self.secret, 2 * 1024 * 1024)

        # The guard is written against the real /data/memory_dumps constant;
        # rebind it to the temp root so the filesystem behaviour is real.
        self.resolve = _load(ROUTES, "_resolve_dump_path",
                             {"_DUMPS_DIR": self.root,
                              "_MIN_DUMP_BYTES": 1024 * 1024})

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def _write(path, size):
        with open(path, "wb") as fh:
            fh.write(b"\0" * size)

    def test_a_real_dump_resolves(self):
        ok, val = self.resolve(self.good)
        self.assertTrue(ok)
        self.assertEqual(val, os.path.realpath(self.good))

    def test_dot_dot_cannot_climb_out(self):
        ok, err = self.resolve(os.path.join(self.root, "..", "elsewhere", "shadow"))
        self.assertFalse(ok)
        self.assertIn("inside", err)

    def test_a_symlink_pointing_out_is_refused(self):
        link = os.path.join(self.root, "innocent.raw")
        os.symlink(self.secret, link)
        ok, err = self.resolve(link)
        self.assertFalse(ok, "a symlink out of the volume is not in the volume")
        self.assertIn("inside", err)

    def test_an_absolute_path_elsewhere_is_refused(self):
        ok, _ = self.resolve(self.secret)
        self.assertFalse(ok)

    def test_a_directory_is_not_a_dump(self):
        ok, err = self.resolve(self.root)
        self.assertFalse(ok)
        self.assertIn("no such dump", err)

    def test_a_missing_file_says_so(self):
        ok, err = self.resolve(os.path.join(self.root, "gone.raw"))
        self.assertFalse(ok)
        self.assertIn("no such dump", err)

    def test_a_stray_small_file_is_not_a_dump(self):
        tiny = os.path.join(self.root, "notes.txt")
        self._write(tiny, 10)
        ok, err = self.resolve(tiny)
        self.assertFalse(ok)
        self.assertIn("too small", err)

    def test_empty_is_refused(self):
        self.assertFalse(self.resolve("")[0])


class TestTheImageIsNotCopied(unittest.TestCase):
    """_staging_relative_path decides upload-vs-register. Getting it wrong is
    silent: the run still works, it just costs a multi-GB duplicate."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.join(self.tmp.name, "memory_dumps")
        os.makedirs(os.path.join(self.root, "_uploads", "abc123"))
        self.rel = _load(PIPELINE, "_staging_relative_path")

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_dump_at_the_top_maps_to_its_name(self):
        p = os.path.join(self.root, "HOST-F.123.raw")
        open(p, "w").close()
        self.assertEqual(self.rel(p, self.root), "HOST-F.123.raw")

    def test_an_upload_keeps_its_subdirectory(self):
        p = os.path.join(self.root, "_uploads", "abc123", "PhysicalMemory.raw")
        open(p, "w").close()
        self.assertEqual(self.rel(p, self.root), "_uploads/abc123/PhysicalMemory.raw")

    def test_a_file_off_the_volume_falls_back_to_upload(self):
        p = os.path.join(self.tmp.name, "somewhere-else.raw")
        open(p, "w").close()
        self.assertIsNone(self.rel(p, self.root),
                          "not on the shared volume — VolWeb cannot see it, it must be uploaded")

    def test_the_volume_root_itself_is_not_a_file(self):
        self.assertIsNone(self.rel(self.root, self.root))


class TestAnUploadLeavesNothingBehind(unittest.TestCase):
    """An upload lands in its own `_uploads/<id>/` directory. Unlinking the
    file leaves that directory behind — one empty directory per upload, for
    ever, on the volume the operator is told to watch for disk."""

    def setUp(self):
        import pathlib
        import typing
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        path = os.path.join(ROOT, "modules/backend/services/memory/cleanup.py")
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        fn = next(n for n in ast.parse(src).body
                  if isinstance(n, ast.FunctionDef) and n.name == "_remove_host_dump")
        ns = {"Path": pathlib.Path, "Callable": typing.Callable}
        exec(compile(ast.get_source_segment(src, fn), path, "exec"), ns)
        self.remove = ns["_remove_host_dump"]
        self.log = lambda m, level="info": None

    def tearDown(self):
        self.tmp.cleanup()

    def test_the_per_upload_directory_goes_with_its_file(self):
        d = self.root / "_uploads" / "abc123"
        d.mkdir(parents=True)
        f = d / "PhysicalMemory.raw"
        f.write_bytes(b"x")
        self.remove(str(f), self.log)
        self.assertFalse(f.exists())
        self.assertFalse(d.exists(), "the empty upload dir was left behind")

    def test_a_top_level_dump_does_not_take_the_dumps_root_with_it(self):
        f = self.root / "HOST-F.1.raw"
        f.write_bytes(b"x")
        self.remove(str(f), self.log)
        self.assertFalse(f.exists())
        self.assertTrue(self.root.exists(), "the dumps directory itself must survive")

    def test_an_upload_dir_holding_anything_else_is_left_alone(self):
        d = self.root / "_uploads" / "keepme"
        d.mkdir(parents=True)
        a, b = d / "a.raw", d / "b.raw"
        a.write_bytes(b"x")
        b.write_bytes(b"x")
        self.remove(str(a), self.log)
        self.assertTrue(b.exists(), "a sibling file was destroyed")
        self.assertTrue(d.exists())


class TestTheRunThatReusesAnImageDoesNotConsumeIt(unittest.TestCase):

    def test_reuse_forces_the_keep(self):
        src = _read("modules/backend/routes/memory_routes.py")
        self.assertIn("if dump_path:\n        # Re-analysing an image the operator deliberately kept.", src)
        blk = src[src.index("keep_dump = _resolve_keep_dump("):][:600]
        self.assertIn("keep_dump = True", blk)

    def test_a_reuse_run_is_marked_as_one(self):
        self.assertIn('"trigger": "reuse" if dump_path else "manual"',
                      _read("modules/backend/routes/memory_routes.py"))

    def test_the_case_purge_leaves_a_reused_image_alone(self):
        """Purging the case that RE-ANALYSED a dump must not delete the image
        out from under the case that owns it."""
        src = _read("modules/backend/services/fusion/store.py")
        self.assertIn('_reused = (det or {}).get("trigger") == "reuse"', src)
        self.assertIn('for key in () if _reused else ("host_path", "upload_dir"):', src)

    def test_acquire_and_reuse_are_mutually_exclusive(self):
        src = _read("modules/backend/routes/memory_routes.py")
        self.assertIn("not both", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
