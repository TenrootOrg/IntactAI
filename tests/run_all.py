#!/usr/bin/env python3
"""Run every consolidated unit-test file in this folder (intact/tests) and tally.

All backend unit tests live here, one (or a few) file(s) per module. pytest is NOT
installed in the backend container, so each file ships an `if __name__ == "__main__"`
runner that prints "<pass>/<total> passed"; this discovers + runs each in its own
subprocess (isolation) and aggregates.

Run inside the backend container (the repo is bind-mounted at /app/workdir):
    docker exec intact_backend python3 /app/workdir/tests/run_all.py

The large fusion subsystem keeps its own coupled suite + calibration:
    docker exec intact_backend python3 /app/services/fusion/tests/run_all.py
"""
import glob
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))


def main():
    # Top-level only. The fusion suite lives in the fusion/ subpackage and MUST be
    # run by its own runner (tests/fusion/run_all.py) which re-execs into a throwaway
    # storage dir — running those files here would hit the LIVE DB.
    files = sorted(set(glob.glob(f"{ROOT}/test_*.py")))
    total = passed = ran = 0
    failures = []
    skipped = []
    for f in files:
        src = open(f).read()
        # A standalone runner is `if __name__ == "__main__"` and nothing else.
        # This also required the literal word "passed", which is a property of
        # the SUMMARY LINE, not of being runnable: 9 suites that print
        # `PASS <name>` and exit non-zero on failure were filed under
        # "pytest-style skipped" and never ran. They read as deliberately
        # deferred, so nothing looked wrong, and a regression in any of them
        # could not fail this gate.
        if "__main__" not in src:
            skipped.append(f)            # pytest-style / no standalone runner
            continue
        ran += 1
        p = subprocess.run([sys.executable, f], capture_output=True, text=True)
        rel = os.path.relpath(f, ROOT)
        # Exit code is the authority. Tally is best-effort across the two formats
        # used in this repo: "<p>/<t> passed" and "<p> passed, <x> xfail, <k> failed".
        m = re.search(r"(\d+)/(\d+) passed", p.stdout)
        if m:
            pp, tt = int(m.group(1)), int(m.group(2))
        else:
            m2 = re.search(r"(\d+) passed", p.stdout)
            if m2:
                pp = tt = int(m2.group(1))
            else:
                # Third format: per-check `PASS <name>` / `FAIL <name>` lines
                # with no numeric trailer. Counting them keeps these suites
                # from contributing 0/0 to the total, which would report a
                # smaller gate than the one that actually ran.
                pp = len(re.findall(r"^PASS ", p.stdout, re.M))
                tt = pp + len(re.findall(r"^FAIL ", p.stdout, re.M))
        total += tt
        passed += pp
        ok = (p.returncode == 0)
        label = f"{pp}/{tt}" if tt else "(exit %d)" % p.returncode
        print(f"  [{'OK ' if ok else 'FAIL'}] {label:>7}  {rel}")
        if not ok:
            failures.append(rel)
            tail = (p.stderr or p.stdout).strip().splitlines()
            if tail:
                print("        " + tail[-1][:140])

    print(f"\n=== {passed}/{total} passed across {ran} standalone test files ===")
    if skipped:
        print(f"({len(skipped)} pytest-style files skipped — run those under CI/pytest)")
    if failures:
        print("FAILED: " + ", ".join(failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
