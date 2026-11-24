"""Import Upgrade Package: what the dashboard route hands the frozen bootstrap,
and how it previews a package.

G3: the installed bootstrap_upgrade.sh is frozen and takes the first bare word
as the release tag. An offline run has no tag, so `--only a,b` reached it as
tag "a,b". The route must send single-token --flag=value forms; this drives the
REAL bootstrap with the route's arguments to prove it no longer sees a tag.

G2: the preview reads <tag>.manifest.json from the head of the wrapper instead
of a full bootstrap --dry-run, and dry runs are one at a time, with a timed-out
run's scratch removed.

The route functions need flask, so they are lifted out with ast and run against
stubs (as test_upgrade_same_version_intact.py does).
"""
import ast
import fcntl
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "modules/backend/routes/upgrade_routes.py")
BOOTSTRAP = os.path.join(ROOT, "scripts/bootstrap_upgrade.sh")
TMP = tempfile.mkdtemp(prefix="upgrade-pkg-routes-")
WORKDIR = os.path.join(TMP, "workdir")
os.makedirs(os.path.join(WORKDIR, "data", "tmp"))
__import__("atexit").register(shutil.rmtree, TMP, True)

_NAMES = ("start_offline_upgrade", "_manifest_from_package", "_dry_run_scratch",
          "_run_dry_run", "_DRY_RUN_LOCK_PATH", "_DRY_RUN_SCRATCH")


def _load():
    tree = ast.parse(open(SRC, encoding="utf-8").read())
    body = []
    for n in tree.body:
        if isinstance(n, ast.FunctionDef) and n.name in _NAMES:
            n.decorator_list = []
            body.append(n)
        elif isinstance(n, ast.Assign) and any(getattr(t, "id", "") in _NAMES for t in n.targets):
            body.append(n)
    ns = {"json": json, "os": os, "shutil": shutil, "subprocess": subprocess,
          "fcntl": fcntl, "time": __import__("time"), "WORKDIR": WORKDIR,
          "jsonify": lambda d: d}
    exec(compile(ast.Module(body=body, type_ignores=[]), SRC, "exec"), ns)
    return ns


NS = _load()


def offline_args(body):
    calls = []
    NS.update({
        "request": types.SimpleNamespace(json=body),
        "_reject_package_path": lambda p: None,
        "_sweep_stale_stages": lambda: None,
        "_sweep_stale_uploads": lambda: None,
        "_stage_for_helper": lambda paths, rid: (["/host/" + os.path.basename(p) for p in paths], None),
        "_start_launcher_run": lambda kind, name, meta, args, force=False: calls.append(args) or ("ok", 202),
    })
    NS["start_offline_upgrade"]()
    return calls[-1]


class SingleTokenArgs(unittest.TestCase):
    def setUp(self):
        self.pkg = os.path.join(TMP, "intact-x-package.tar")
        open(self.pkg, "w").close()

    def test_offline_args_are_single_token(self):
        args = offline_args({"package_path": self.pkg, "selected_modules": ["elk", "iris"],
                             "reinstall_modules": ["iris"], "expected_sha256": "ab" * 32})
        self.assertEqual(["--package", "/host/intact-x-package.tar", "--only=elk,iris",
                          "--reinstall=iris", "--expect-sha256=" + "ab" * 32], args)

    def test_the_frozen_bootstrap_sees_no_tag(self):
        """Run the real bootstrap on the route's args. Without an engine it
        refuses, and its refusal names the tag it parsed -- there must be none.
        curl is faked so nothing is fetched."""
        args = offline_args({"package_path": self.pkg, "selected_modules": ["elk", "iris"],
                             "reinstall_modules": ["iris"], "expected_sha256": "ab" * 32})
        args = [self.pkg if a.startswith("/host/") else a for a in args]
        appliance = os.path.join(TMP, "appliance")
        bindir = os.path.join(TMP, "bin")
        os.makedirs(os.path.join(appliance, "data", "tmp"), exist_ok=True)
        os.makedirs(bindir, exist_ok=True)
        open(os.path.join(appliance, "config.yaml"), "w").close()
        with open(os.path.join(bindir, "curl"), "w") as fh:
            fh.write("#!/bin/sh\nexit 7\n")
        os.chmod(os.path.join(bindir, "curl"), 0o755)
        if os.geteuid() == 0:
            self.skipTest("as root the bootstrap would use /var/lib/intact/engine")
        env = dict(os.environ, PATH=bindir + os.pathsep + os.environ["PATH"])
        r = subprocess.run(["bash", BOOTSTRAP, "--root", appliance] + args,
                           capture_output=True, text=True, timeout=60, env=env)
        out = r.stdout + r.stderr
        self.assertNotEqual(0, r.returncode)
        self.assertIn("could not obtain the upgrade engine", out)
        self.assertNotIn("elk,iris upgrade engine", out)
        # The two-token form, for contrast: the bootstrap took the value as the tag.
        r2 = subprocess.run(["bash", BOOTSTRAP, "--root", appliance, "--package", self.pkg,
                             "--only", "elk,iris"], capture_output=True, text=True, timeout=60, env=env)
        self.assertIn("could not obtain the elk,iris upgrade engine", r2.stdout + r2.stderr)


class ManifestFromWrapper(unittest.TestCase):
    def _wrapper(self, members):
        d = tempfile.mkdtemp(dir=TMP)
        path = os.path.join(d, "w.tar")
        with tarfile.open(path, "w") as tf:
            for name, data in members:
                f = os.path.join(d, name)
                with open(f, "wb") as fh:
                    fh.write(data)
                tf.add(f, arcname=name)
        return path

    def test_reads_the_merged_manifest_and_drops_its_checksums(self):
        man = {"versions": {"intact": "intact-x", "elk": "9.6.0"}, "created": "now",
               "contents": {"sha256": {"a": "b"}, "release_tag": "intact-x"}}
        p = self._wrapper([("intact-x.index.json", b'{"assets": {}}'),
                           ("intact-x.manifest.json", json.dumps(man).encode()),
                           ("intact-x-elk.tar.gz", b"\0" * 4096)])
        doc = NS["_manifest_from_package"](p)
        self.assertEqual({"intact": "intact-x", "elk": "9.6.0"}, doc["versions"])
        self.assertEqual("now", doc["created"])
        self.assertNotIn("sha256", doc["contents"])

    def test_falls_back_to_the_index(self):
        p = self._wrapper([("intact-x.index.json",
                            b'{"release_tag": "intact-x", "assets": {"elk": {"version": "9.6.0"}}}'),
                           ("intact-x-elk.tar.gz", b"\0")])
        self.assertEqual({"elk": "9.6.0"}, NS["_manifest_from_package"](p)["versions"])

    def test_nothing_known_means_ask_the_engine(self):
        p = self._wrapper([("intact-x-elk.tar.gz", b"\0")])
        self.assertIsNone(NS["_manifest_from_package"](p))

    def test_a_manifest_deeper_in_the_tree_is_not_read(self):
        p = self._wrapper([("sub", b"")])
        with tarfile.open(p, "a") as tf:
            info = tarfile.TarInfo("source/x.manifest.json")
            data = b'{"versions": {"elk": "1"}}'
            info.size = len(data)
            import io
            tf.addfile(info, io.BytesIO(data))
        self.assertIsNone(NS["_manifest_from_package"](p))

    def test_directory_package(self):
        d = tempfile.mkdtemp(dir=TMP)
        with open(os.path.join(d, "intact-x.manifest.json"), "w") as fh:
            json.dump({"versions": {"iris": "v2.4.29"}}, fh)
        self.assertEqual({"iris": "v2.4.29"}, NS["_manifest_from_package"](d)["versions"])


class OneDryRunAtATime(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.join(WORKDIR, "data", "tmp")
        NS["_upgrade_gate"] = lambda: None

    def test_a_second_dry_run_is_refused(self):
        fd = os.open(NS["_DRY_RUN_LOCK_PATH"], os.O_CREAT | os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            NS["run_command"] = lambda *a, **k: self.fail("must not run")
            self.assertIsNone(NS["_run_dry_run"]("x", 1))
        finally:
            os.close(fd)

    def _timed_out(self, *a, **k):
        os.makedirs(os.path.join(self.tmp, "upgrade-pkg-new"))
        open(os.path.join(self.tmp, "upgrade-handoff-99.json"), "w").close()
        return {"success": False, "error": "Command timed out after 1s"}

    def test_a_timed_out_run_loses_only_its_own_scratch(self):
        os.makedirs(os.path.join(self.tmp, "upgrade-pkg-older"), exist_ok=True)
        NS["run_command"] = self._timed_out
        NS["_run_dry_run"]("x", 1)
        left = os.listdir(self.tmp)
        self.assertNotIn("upgrade-pkg-new", left)
        # a handoff may be a real Apply's, written before its engine took the lock
        self.assertIn("upgrade-handoff-99.json", left)
        self.assertIn("upgrade-pkg-older", left, "scratch from before this run is the sweep's")
        shutil.rmtree(os.path.join(self.tmp, "upgrade-pkg-older"))
        os.unlink(os.path.join(self.tmp, "upgrade-handoff-99.json"))

    def test_nothing_is_removed_while_an_upgrade_holds_the_lock(self):
        NS["_upgrade_gate"] = lambda: ("busy", 409)
        NS["run_command"] = self._timed_out
        NS["_run_dry_run"]("x", 1)
        self.assertIn("upgrade-pkg-new", os.listdir(self.tmp))
        shutil.rmtree(os.path.join(self.tmp, "upgrade-pkg-new"))
        os.unlink(os.path.join(self.tmp, "upgrade-handoff-99.json"))


if __name__ == "__main__":
    unittest.main()
