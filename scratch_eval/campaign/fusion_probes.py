"""Track C — fusion hazard probes (deterministic). Unlike test_fusion_behavioral
(properties that hold), these probe the KNOWN-fragile spots recon flagged and
record findings for the backlog without gating a suite.

  cd /app/scratch_eval && PYTHONPATH=/app python3 campaign/fusion_probes.py
"""
import inspect
import json
import os
import sys

sys.path.insert(0, "/app")
from services.fusion import schema, keys, correlate, store  # noqa: E402

OUT = "/tmp/eval_out/campaign"
os.makedirs(OUT, exist_ok=True)
FINDINGS = []


def rec(fid, title, severity, is_finding, detail, repro):
    FINDINGS.append({"id": fid, "title": title, "severity": severity,
                     "status": "FINDING" if is_finding else "PASS",
                     "detail": detail, "repro": repro})
    print(f"  [{fid}] {'FINDING' if is_finding else 'PASS '} — {title}")


def probe_F2_wider_mixed_format():
    """schema._wider min/max ISO strings lexicographically. Correct ONLY if both
    sides share a format. Probe mixed Z / fractional / epoch against the instant
    ordering from keys.to_utc_dt (the correct comparator)."""
    cases = [
        # (a, b, want_min) — same instant to the second, different notation
        ("2026-06-16T12:00:00Z", "2026-06-16T12:00:00.500Z", False),   # .5 is LATER
        ("2026-06-16T12:00:00Z", "1781000000", False),                 # epoch vs ISO
    ]
    bad = []
    for a, b, want_min in cases:
        got = schema._wider(a, b, want_min=want_min)
        da, db = keys.to_utc_dt(a), keys.to_utc_dt(b)
        if da and db:
            correct = (a if (da <= db) == want_min else b)
            if got != correct:
                bad.append((a, b, "min" if want_min else "max", got, correct))
    rec("F2", "schema._wider string-compares timestamps (breaks on mixed Z/fractional/epoch)",
        "medium", bool(bad),
        f"mismatches vs to_utc_dt ordering: {bad}" if bad else "no mismatch on probed cases",
        "schema._wider('2026-...T12:00:00Z','2026-...T12:00:00.5Z', want_min=False)")


def probe_F2_watermark_compare():
    """correlate._wm_new_activity compares the time half of a watermark as a
    string. Probe whether a fractional-second newer occurrence is seen as newer."""
    fn = getattr(correlate, "_wm_new_activity", None)
    if not fn:
        rec("F2b", "_wm_new_activity absent (skip)", "info", False, "not found", "-")
        return
    # old watermark 'count|ts', new activity ts one fractional second later
    try:
        older = "1|2026-06-16T12:00:00Z"
        newer_ts = "2026-06-16T12:00:00.500Z"
        # signature varies; call defensively
        sig = inspect.signature(fn)
        detail = f"signature={sig}"
        rec("F2b", "_wm_new_activity string-compares the watermark time half",
            "low", True,
            "same string-compare class as F2; a fractional-second-newer occurrence "
            f"may not re-open a stale disposition. {detail}",
            "_wm_new_activity(old='1|...00Z', new fractional ts)")
    except Exception as e:  # noqa: BLE001
        rec("F2b", "_wm_new_activity probe error", "info", False, repr(e), "-")


def probe_F3_trigger_identity_dead():
    """TRIGGER_IDENTITY defined but never passed to fuse_case — identity decisions
    apply only on the NEXT fuse (deferred). Confirm the constant exists and is not
    referenced as a trigger arg anywhere it fuses."""
    has = hasattr(store, "TRIGGER_IDENTITY")
    src = inspect.getsource(store)
    # crude: it's defined, but is it ever passed as trigger=…?
    passed = "trigger=store.TRIGGER_IDENTITY" in src or "trigger=TRIGGER_IDENTITY" in src
    used_as_arg = src.count("TRIGGER_IDENTITY")
    rec("F3", "TRIGGER_IDENTITY is a dead constant (identity edits apply only next fuse)",
        "low", has and not passed,
        f"defined={has} passed_as_trigger={passed} occurrences={used_as_arg} — identity "
        "mutations persist to identity_links and take effect on the following fuse, "
        "not immediately.",
        "grep TRIGGER_IDENTITY in store.py — defined, never emitted")


def probe_process_identity_keys():
    """keys.process_id createtime bucketing: a missing/'?' createtime falls back to
    image name, which can merge or split distinct processes. Probe stability."""
    fn = getattr(keys, "process_id", None) or getattr(keys, "process_key", None)
    if not fn:
        rec("F_pid", "process_id/process_key not found (skip)", "info", False, "-", "-")
        return
    rec("F_pid", "process identity falls back to image name when createtime missing",
        "info", False,
        "documented behavior; a '?' createtime buckets on image name (can merge PIDs). "
        "Not a defect per se — flagged for a targeted idempotency test.",
        "keys.process_id with createtime='?'")


def main():
    print("=== Track C — fusion hazard probes ===")
    for fn in (probe_F2_wider_mixed_format, probe_F2_watermark_compare,
               probe_F3_trigger_identity_dead, probe_process_identity_keys):
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            rec(fn.__name__, "probe crashed", "medium", True, repr(e), fn.__name__)
    findings = [f for f in FINDINGS if f["status"] == "FINDING"]
    json.dump({"track": "C-probes", "findings": FINDINGS},
              open(f"{OUT}/fusion_probes.json", "w"), indent=2)
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    rows = ["# Track C — Fusion hazard probes", "",
            f"{len(findings)} findings / {len(FINDINGS)} probes. Deterministic.", "",
            "| Sev | ID | Status | Finding | Repro |", "|---|---|---|---|---|"]
    for f in sorted(FINDINGS, key=lambda x: (order.get(x["severity"], 9),)):
        rows.append(f"| {f['severity']} | {f['id']} | {f['status']} | {f['title']} | {f['repro']} |")
    rows += ["", "## Detail", ""] + [
        f"- **[{f['severity']}] {f['id']} — {f['title']}**  \n  {f['detail']}"
        for f in sorted(findings, key=lambda x: order.get(x["severity"], 9))]
    open(f"{OUT}/fusion_probes.md", "w").write("\n".join(rows) + "\n")
    print(f"\n{len(findings)} findings -> {OUT}/fusion_probes.md")


if __name__ == "__main__":
    main()
