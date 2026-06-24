"""Run every fusion test module + print the calibrate.py F1 — the one-command
'fix test fix test' loop.

    docker exec -w /app intact_backend python3 -m services.fusion.tests.run_all
"""

# Test isolation: these tests import services.* (which boots SQLite storage at
# import time) and create real workspaces/runs. By the time this module's body
# runs the `services` package is already imported, so we cannot redirect storage
# in-process — instead re-exec ONCE into a throwaway storage dir. The fresh
# process imports storage against the temp DB, so the suite never touches the
# live /app/data/intact.db. MUST be the first thing that runs.
import os as _os
import sys as _sys
if not _os.environ.get("FUSION_TEST_ISOLATED"):
    import tempfile as _tempfile
    _tmp = _tempfile.mkdtemp(prefix="fusion-test-store-")
    _os.environ["FUSION_TEST_ISOLATED"] = "1"
    _os.environ["INTACT_STORAGE_BASE"] = _tmp
    print(f"[run_all] isolating storage -> {_tmp} (re-exec)", flush=True)
    _os.execv(_sys.executable,
              [_sys.executable, "-m", "services.fusion.tests.run_all"] + _sys.argv[1:])

import sys
import importlib

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

MODULES = [
    "services.fusion.tests.test_fusion",
    "services.fusion.tests.test_details_parser",
    "services.fusion.tests.test_detection_linking",
    "services.fusion.tests.test_hash_bridge",
    "services.fusion.tests.test_auth_kerberos",
    "services.fusion.tests.test_blindspot_mappers",
    "services.fusion.tests.test_analysis_contract",
    "services.fusion.tests.test_case_routes",
    "services.fusion.tests.test_workspaces",
    "services.fusion.tests.test_dispositions",
    "services.fusion.tests.test_validation_attack2",
    "services.fusion.tests.test_no_llm",
    "services.fusion.tests.test_time_filter",
    "services.fusion.tests.test_budget",
    "services.fusion.tests.test_llm_contract",
    "services.fusion.tests.test_baseline_fp",
    "services.fusion.tests.test_baseline_subtraction",
    "services.fusion.tests.test_chat_retrieval",
    "services.fusion.tests.test_kb_enrichment",
    "services.fusion.tests.test_fuzz_mappers",
    "services.fusion.tests.test_event_dedup",
    "services.fusion.tests.test_timeline",
]


def _run_module(modname):
    mod = importlib.import_module(modname)
    fns = [getattr(mod, n) for n in dir(mod)
           if n.startswith("test_") and callable(getattr(mod, n))]
    xred = bool(getattr(mod, "EXPECTED_RED", False))
    p = xf = hard = 0
    for fn in fns:
        try:
            fn(); p += 1
        except AssertionError as e:
            if xred:
                xf += 1
            else:
                hard += 1
                print(f"  FAIL {modname}.{fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            hard += 1
            print(f"  ERROR {modname}.{fn.__name__}: {e!r}")
    tag = f"{p} pass" + (f", {xf} xfail" if xf else "") + (f", {hard} FAIL" if hard else "")
    print(f"{modname.split('.')[-1]:24} {tag}")
    return p, xf, hard


def main():
    tot_p = tot_xf = tot_hard = 0
    for m in MODULES:
        p, xf, hard = _run_module(m)
        tot_p += p; tot_xf += xf; tot_hard += hard
    print(f"\n=== TOTAL: {tot_p} pass, {tot_xf} xfail, {tot_hard} FAIL ===")
    try:
        from services.fusion import calibrate
        print("--- calibration ---")
        calibrate.evaluate()
    except Exception as e:  # noqa: BLE001
        print(f"calibrate skipped: {e!r}")
    return 1 if tot_hard else 0


if __name__ == "__main__":
    sys.exit(main())
