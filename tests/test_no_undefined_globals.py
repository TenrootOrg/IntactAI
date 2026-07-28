"""Every global a backend function loads must actually exist.

This catches the NameError-on-a-rare-line bug class: code that imports fine,
passes review and only explodes when one specific branch runs -- typically an
error path, or a success path that a test never reached.

It has caught two real ones:

  * routes/upgrade_routes.py -- the Prepare Package success response
    interpolated len(modules) in a route that only takes `target`. The run was
    created and its thread started BEFORE the response was built, so the
    operator saw "Upgrade request failed: name 'modules' is not defined" for a
    preparation that was actually running, and the retry was then refused with
    "already in progress".
  * services/upgrade/timesketch.py -- upgrade_timesketch read an undefined
    `health` while building its SUCCESS result, inside a try whose except
    performs a rollback. A fully successful online Timesketch upgrade raised
    NameError on its last line and got rolled back.

How it works: a name the compiler resolves as a global emits LOAD_GLOBAL, so
the bytecode names exactly what a function will look up at runtime. Each is
checked against that function's OWN __globals__ (not the module being scanned
-- an imported function resolves against the module that defined it) plus
builtins. Names assigned anywhere in a function are locals and compile to
LOAD_FAST, so they never appear here: no false positives from conditional
imports, walrus assignments or late definitions. Nested functions, closures
and comprehensions are reached through co_consts.

This is a static check -- it never calls the functions it scans.

Run:  docker exec intact_backend python /app/workdir/tests/test_no_undefined_globals.py
"""

import builtins
import dis
import importlib
import os
import sys
import types

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

# Packages whose functions must fully resolve. `routes` is the HTTP surface
# (an undefined name there is a 500 the operator sees); `services` is the
# upgrade/fusion engine (an undefined name there can trigger a rollback).
SCAN_PACKAGES = ("routes", "services")
APP_ROOT = "/app"


def _iter_code(code):
    """The code object and every nested one (defs, lambdas, comprehensions)."""
    yield code
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            yield from _iter_code(const)


def _module_names():
    for pkg in SCAN_PACKAGES:
        base = os.path.join(APP_ROOT, pkg)
        if not os.path.isdir(base):
            continue
        for root, _dirs, files in os.walk(base):
            if "__pycache__" in root:
                continue
            for f in sorted(files):
                if not f.endswith(".py") or f == "__init__.py":
                    continue
                rel = os.path.join(root, f)[len(APP_ROOT) + 1:-3]
                yield rel.replace(os.sep, ".")


def _undefined_globals_in(module):
    """[(qualname, missing_name)] for functions DEFINED in this module."""
    found = []
    for obj in vars(module).values():
        fn = getattr(obj, "__wrapped__", obj)   # see through @decorators
        if not isinstance(fn, types.FunctionType):
            continue
        if fn.__module__ != module.__name__:    # imported — not ours to judge
            continue
        g = fn.__globals__
        for code in _iter_code(fn.__code__):
            for ins in dis.get_instructions(code):
                if ins.opname != "LOAD_GLOBAL":
                    continue
                name = ins.argval
                if name in g or hasattr(builtins, name):
                    continue
                found.append((f"{module.__name__}:{code.co_name}", name))
    return found


def test_no_undefined_globals():
    missing, import_failures, scanned = [], [], 0

    for mod_name in _module_names():
        try:
            module = importlib.import_module(mod_name)
        except Exception as e:                   # noqa: BLE001 — reported, not raised
            import_failures.append(f"{mod_name}: {type(e).__name__}: {e}")
            continue
        scanned += 1
        missing.extend(_undefined_globals_in(module))

    assert scanned > 0, "scanned no modules — is the backend source mounted at /app?"

    assert not import_failures, (
        "backend modules failed to import, so they were never scanned:\n  "
        + "\n  ".join(sorted(import_failures))
    )

    assert not missing, (
        "functions reference globals that do not exist — these raise NameError "
        "the moment that line runs:\n  "
        + "\n  ".join(f"{where} -> {name}" for where, name in sorted(set(missing)))
    )

    print(f"  scanned {scanned} modules across {', '.join(SCAN_PACKAGES)}")


def test_the_scan_detects_a_planted_undefined_global():
    """Guard against the check silently becoming a no-op (e.g. if LOAD_GLOBAL
    stops being emitted, or the decorator/closure walk breaks). A scan that
    finds nothing because it looks at nothing would still 'pass' above."""
    src = (
        "def outer():\n"
        "    def inner():\n"
        "        return [definitely_not_defined_anywhere for _ in range(1)]\n"
        "    return inner\n"
    )
    module = types.ModuleType("planted_bug_module")
    module.__name__ = "planted_bug_module"
    exec(compile(src, "<planted>", "exec"), module.__dict__)

    hits = _undefined_globals_in(module)
    assert any(n == "definitely_not_defined_anywhere" for _, n in hits), (
        "the scan failed to spot a planted undefined global inside a nested "
        "function's comprehension — it is no longer catching this bug class"
    )


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as e:
                failures += 1
                print(f"FAIL {name}: {e}")
    print("OK" if not failures else f"{failures} FAILED")
    sys.exit(1 if failures else 0)
