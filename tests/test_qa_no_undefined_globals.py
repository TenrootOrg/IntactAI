"""Every global the QA harness loads must actually exist.

A phase function that references a name nothing assigns is a NameError that
only fires when that line executes — which, for the QA harness, is fourteen
minutes into a run, after an endpoint has been enrolled, infected and
collected from. That is exactly what happened: rewriting the VolWeb yara block
removed the assignment to `hit_count` while the return statement below still
referenced it, and the whole phase errored out at the very end.

The mechanism is the same one tests/test_no_undefined_globals.py uses on the
backend: when the compiler cannot resolve a name as a local it emits
LOAD_GLOBAL, so a deleted local assignment turns silently into a global lookup.
Disassembling every function and checking those names against the module's own
globals plus builtins catches it in milliseconds instead of a quarter of an
hour.

Run: python3 tests/test_qa_no_undefined_globals.py
"""

import builtins
import dis
import importlib
import os
import sys
import types

REPO = os.environ.get("INTACT_PATH") or os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))
QA_ROOT = os.path.join(REPO, "qa")
MODULES = ("lib.api", "lib.config", "lib.redact", "lib.runner", "lib.shell",
           "lib.timeline", "lib.winssh",
           "phases.platform", "phases.endpoint", "phases.workflows",
           "phases.wrapup")


def _functions(obj, seen=None):
    """Every function reachable from a module, including nested ones —
    phase bodies are closures registered by a decorator, so a scan that only
    looked at module-level functions would miss all of them."""
    seen = seen if seen is not None else set()
    for const in getattr(obj, "co_consts", ()) or ():
        if isinstance(const, types.CodeType):
            if id(const) not in seen:
                seen.add(id(const))
                yield const
                yield from _functions(const, seen)


def test_no_undefined_globals_in_the_harness():
    if QA_ROOT not in sys.path:
        sys.path.insert(0, QA_ROOT)

    problems = []
    for name in MODULES:
        try:
            mod = importlib.import_module(name)
        except Exception as exc:                              # noqa: BLE001
            problems.append(f"{name}: import failed: {exc}")
            continue

        known = set(vars(mod)) | set(dir(builtins))
        src = getattr(mod, "__file__", "")
        try:
            with open(src, encoding="utf-8") as fh:
                code = compile(fh.read(), src, "exec")
        except Exception as exc:                              # noqa: BLE001
            problems.append(f"{name}: compile failed: {exc}")
            continue

        for fn_code in _functions(code):
            for ins in dis.get_instructions(fn_code):
                if ins.opname != "LOAD_GLOBAL":
                    continue
                ref = ins.argval
                if ref not in known:
                    line = ins.positions.lineno if ins.positions else "?"
                    problems.append(
                        f"{name}.{fn_code.co_name}: loads undefined global "
                        f"{ref!r} (line {line})")

    assert not problems, "undefined globals in the QA harness:\n  " + \
        "\n  ".join(sorted(set(problems)))


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
