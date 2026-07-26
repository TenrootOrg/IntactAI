"""Run every fusion test module + print the calibrate.py F1 — the one-command
'fix test fix test' loop.

    docker exec -w /app intact_backend python3 -m tests.fusion.run_all
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
              [_sys.executable, "-m", "tests.fusion.run_all"] + _sys.argv[1:])

import sys
import importlib

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

MODULES = [
    "tests.fusion.test_fusion",
    "tests.fusion.test_details_parser",
    "tests.fusion.test_detection_linking",
    "tests.fusion.test_hash_bridge",
    "tests.fusion.test_auth_kerberos",
    "tests.fusion.test_blindspot_mappers",
    "tests.fusion.test_analysis_contract",
    "tests.fusion.test_case_routes",
    "tests.fusion.test_workspaces",
    "tests.fusion.test_dispositions",
    "tests.fusion.test_chat_never_mutates",
    "tests.fusion.test_chat_robustness",
    "tests.fusion.test_identities_in_chat_payload",
    "tests.fusion.test_validation_attack2",
    "tests.fusion.test_no_llm",
    "tests.fusion.test_time_filter",
    "tests.fusion.test_budget",
    "tests.fusion.test_llm_contract",
    "tests.fusion.test_baseline_fp",
    "tests.fusion.test_baseline_subtraction",
    "tests.fusion.test_chat_retrieval",
    "tests.fusion.test_chat_resolve",
    "tests.fusion.test_masking",
    "tests.fusion.test_kb_enrichment",
    "tests.fusion.test_fuzz_mappers",
    "tests.fusion.test_event_dedup",
    "tests.fusion.test_memory_mapper",
    "tests.fusion.test_cloud_fusion",
    "tests.fusion.test_identities",
    "tests.fusion.test_risk_scoring",
    "tests.fusion.test_timeline",
    "tests.fusion.test_report_detail",
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
