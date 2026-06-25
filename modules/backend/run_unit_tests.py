#!/usr/bin/env python3
"""Run every standalone unit-test file under modules/backend and print a tally.

pytest is NOT installed in the backend container, so each unit-test file ships a
`if __name__ == "__main__"` runner that prints "<pass>/<total> passed". This script
discovers those files, runs each in its own subprocess (isolation), and aggregates.

Run inside the backend container (the repo is bind-mounted at /app/workdir):
    docker exec intact_backend python3 /app/workdir/modules/backend/run_unit_tests.py

The fusion module also has its own richer runner with calibration metrics:
    docker exec intact_backend python3 /app/services/fusion/tests/run_all.py
"""
import glob
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))


def main():
    files = sorted(set(glob.glob(f"{ROOT}/**/test_*.py", recursive=True)))
    total = passed = ran = 0
    failures = []
    skipped = []
    for f in files:
        src = open(f).read()
        if "__main__" not in src or "passed" not in src:
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
            pp = tt = int(m2.group(1)) if m2 else 0
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
