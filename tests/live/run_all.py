#!/usr/bin/env python3
"""Run the live-HTTP integration suite (tests/live/) against the REAL running
stack and tally PASS/FAIL/SKIP per feature area.

    docker exec intact_backend python3 /app/workdir/tests/live/run_all.py
    docker exec intact_backend python3 /app/workdir/tests/live/run_all.py case_management
    docker exec intact_backend python3 /app/workdir/tests/live/run_all.py --no-sweep

Unlike tests/run_all.py (fast, in-process unit tests), every file here makes
real HTTP calls to the live backend and can take minutes per file, and the
whole suite can take a long time. NOT swept by tests/run_all.py; invoke by
name, or via this runner, only when asked.

Each test_*.py file is independently runnable
(`python3 tests/live/test_<area>.py`) and prints a trailer line matching
"N passed, M failed, K skipped" — this runner regexes that line out of each
subprocess's stdout rather than importing the files, so one area's crash
can never corrupt another area's state (each runs in its own process, with
its own LiveCase/cleanup lifecycle).
"""
import argparse
import glob
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
TRAILER_RE = re.compile(r"(\d+) passed, (\d+) failed, (\d+) skipped")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("area", nargs="?", help="substring to match one or more test_<area>.py files (default: all)")
    ap.add_argument("--sweep-first", dest="sweep_first", action="store_true", default=True,
                     help="run cleanup_sweep.py before the suite (default: on)")
    ap.add_argument("--no-sweep", dest="sweep_first", action="store_false",
                     help="skip the pre-run cleanup sweep")
    args = ap.parse_args()

    if args.sweep_first:
        print("=== pre-run cleanup sweep (leftovers from a prior crashed/killed run) ===", flush=True)
        subprocess.run([sys.executable, os.path.join(ROOT, "cleanup_sweep.py")])
        print(flush=True)

    files = sorted(glob.glob(os.path.join(ROOT, "test_*.py")))
    if args.area:
        matched = [f for f in files if args.area in os.path.basename(f)]
        if not matched:
            print(f"No test_*.py file matches '{args.area}'. Available files:")
            for f in files:
                print(f"  {os.path.basename(f)}")
            return 1
        files = matched

    totals = {"pass": 0, "fail": 0, "skip": 0}
    per_area = []
    failed_areas = []

    for f in files:
        rel = os.path.relpath(f, ROOT)
        print(f"--- {rel} ---", flush=True)
        p = subprocess.run([sys.executable, f], capture_output=True, text=True)
        m = TRAILER_RE.search(p.stdout)
        pp, ff, ss = (int(x) for x in m.groups()) if m else (0, 0, 0)
        totals["pass"] += pp
        totals["fail"] += ff
        totals["skip"] += ss
        # A file that crashed before printing its own trailer (import error,
        # unhandled exception outside its own try/except) is a real failure
        # even though our regex found nothing to tally.
        crashed = m is None and p.returncode != 0
        ok = p.returncode == 0 and not crashed
        per_area.append((rel, pp, ff, ss, ok))
        status = "OK  " if ok else "FAIL"
        print(f"  [{status}] {pp}P/{ff}F/{ss}S  (exit {p.returncode})", flush=True)
        if not ok:
            failed_areas.append(rel)
            tail = (p.stderr or p.stdout).strip().splitlines()
            if tail:
                print(f"        last line: {tail[-1][:200]}", flush=True)
        print(flush=True)

    print("=== summary ===")
    for rel, pp, ff, ss, ok in per_area:
        print(f"  {'OK  ' if ok else 'FAIL'}  {pp:3d}P {ff:3d}F {ss:3d}S  {rel}")
    print(f"\n=== {totals['pass']} passed, {totals['fail']} failed, {totals['skip']} skipped "
          f"across {len(files)} area(s) ===")
    if failed_areas:
        print("FAILED AREAS: " + ", ".join(failed_areas))

    return 1 if failed_areas else 0


if __name__ == "__main__":
    sys.exit(main())
