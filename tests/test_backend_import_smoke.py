"""Import every backend module for real, with the heavy third-party deps stubbed.

WHY. The two AST lints next door (test_backend_name_binding.py,
test_no_undefined_names.py) read source; they never run it. So a mechanical edit
-- dropping an import a linter calls unused, deleting a function nothing appears
to call -- can pass every existing check and still explode at container start,
because the name was used at MODULE scope: a decorator argument, a default
argument, a re-export, a class base. Nothing in this suite imported a route
module at all; test_case_fuse_races.py:19 records the belief that it is
impossible ("cannot be imported here, that pulls the whole backend"). That is
true only WITHOUT stubs.

WHY A SUBPROCESS. The stubs are process-global. Installing a fake `flask` in
this interpreter makes every other test that guards on `import flask` believe
flask is present, so tests that should skip instead run against the fake and
fail -- measured: test_case_fuse_races.py goes from "2 skipped" to "2 failed"
the moment this file is imported first. run_tests.sh:6-9 already made exactly
this call for the shell suites ("one file's stubbed collaborators can never leak
into another's"); this is the same decision for Python.

Import-time side effects are real and are redirected, not suppressed:
  services/storage/base.py:18    STORAGE_BASE = env INTACT_STORAGE_BASE or /app/data
  services/storage/__init__.py   init_storage()            -> creates the sqlite db
  services/scheduler/__init__.py init_scheduled_jobs_table()
  routes/blueprint_routes.py     seed_default_blueprints()
All write to that base, so pointing it at a temp dir before the first import is
enough. The writes still happen -- that is the point, they are code under test.

Verified by breaking something on purpose: comment out the flask import in
routes/aws_routes.py and this turns red with "NameError: name 'Blueprint' is not
defined"; restore it and it turns green.
"""

import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, "modules/backend")

# module name -> why it cannot be imported here. Empty is the goal: an entry is
# a documented hole, not a silent pass.
KNOWN_SKIP = {
    # Not a backend module: a build-time script the Dockerfile runs as
    # `python3 /app/install_deps.py /app/config.yaml /app` (Dockerfile:71). It
    # reads sys.argv at module scope, so importing it under pytest makes it try
    # to open pytest's own flag as a config file. app.py never imports it.
    "install_deps": "Dockerfile build script; reads sys.argv at import",
}


def _module_names():
    """Dotted names for every .py under modules/backend."""
    for dirpath, dirnames, filenames in os.walk(BACKEND):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for f in sorted(filenames):
            if not f.endswith(".py"):
                continue
            rel = os.path.relpath(os.path.join(dirpath, f), BACKEND)
            parts = rel[:-3].split(os.sep)
            if parts[-1] == "__init__":
                parts = parts[:-1]
            if parts:
                yield ".".join(parts)


def _child():
    """Runs in its own interpreter: stub, then import everything."""
    import importlib
    import tempfile

    os.environ.setdefault("INTACT_STORAGE_BASE",
                          tempfile.mkdtemp(prefix="intact-smoke-"))
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, BACKEND)

    import _optional_deps

    # Every third-party top-level import that appears under modules/backend.
    # stub() is a no-op for anything genuinely installed, so a box that has
    # flask tests the real flask.
    _optional_deps.stub(
        "flask", "flask_cors", "werkzeug", "grpc", "pyvelociraptor", "apscheduler",
        "elasticsearch", "dateutil", "markdown", "urllib3", "requests", "yaml",
        "boto3", "botocore", "msal", "azure", "psutil", "docker", "jwt", "bcrypt",
    )

    names = sorted(set(_module_names()))
    if len(names) < 100:
        print(f"the walker found only {len(names)} modules", file=sys.stderr)
        return 2
    bad = 0
    for name in names:
        if name in KNOWN_SKIP:
            continue
        try:
            importlib.import_module(name)
        except Exception as e:
            bad += 1
            print(f"{name}: {type(e).__name__}: {e}", file=sys.stderr)
    print(f"imported {len(names) - len(KNOWN_SKIP) - bad}/"
          f"{len(names) - len(KNOWN_SKIP)} modules")
    return 1 if bad else 0


class TestEveryBackendModuleImports(unittest.TestCase):
    def test_every_backend_module_imports(self):
        r = subprocess.run([sys.executable, os.path.abspath(__file__), "--child"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0,
                         f"\n{r.stdout}\n{r.stderr}")


if __name__ == "__main__":
    if "--child" in sys.argv:
        sys.exit(_child())
    unittest.main(verbosity=2)
