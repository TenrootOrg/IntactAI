"""Run every fusion test module + print the calibrate.py F1 — the one-command
'fix test fix test' loop.

    docker exec -w /app intact_backend python3 -m services.fusion.tests.run_all
"""

import sys
import importlib

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

MODULES = [
    "services.fusion.tests.test_fusion",
    "services.fusion.tests.test_budget",
    "services.fusion.tests.test_baseline_fp",
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
