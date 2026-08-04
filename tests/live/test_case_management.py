#!/usr/bin/env python3
"""Live Case Management checks — real backend API calls against the live stack.

Covers modules/backend/routes/case_routes.py — the biggest single feature
area in the platform (44 routes: workspace CRUD, member-run attach/fuse,
config/rescan, Identities tab, timeline, checklist, branding/report
(md + pdf), graph/analysis/dispositions/metrics reads, disposition, and
export/import). This is the biggest, most involved file in tests/live/ —
one composite lifecycle check exercises nearly every route in one real
case, end to end, plus a second check for the one-call /api/cases/quick
path.

Member data: a fast synthetic AWS CloudTrail offline-analysis run (same
fixture live_smoke.py's check_aws_sigma uses via
_lib.synthetic_cloudtrail_event()), so this needs no live cloud creds and
completes in seconds. Two things confirmed by reading the actual code
(not assumed from the plan doc) that change how this file works:

  1. POST /api/aws/upload reads request.files (multipart), NOT a JSON
     body — confirmed by direct testing; a JSON POST (the shape
     live_smoke.py's check_aws_sigma currently sends) gets a 400 "No
     files provided". This file uses `requests` directly with a real
     multipart upload instead of _lib._post.
  2. A case's fusion only includes "velociraptor_agentic" + "memory" by
     default (services/fusion/store.py: FUSION_MODULES_DEFAULT) — "aws"
     is AVAILABLE but opt-in. An AWS-sourced case fuses 0 entities unless
     POST /api/cases/<id>/config explicitly sets fusion_modules to include
     "aws". The full-lifecycle check does this before attaching so the
     rest of the flow (checklist, graph findings, disposition) has real
     data to exercise; case_quick_create deliberately does NOT (the quick
     endpoint has no fusion_modules param at all), so it documents 0
     entities as the expected outcome rather than a bug.

NOT part of run_all.py's sweep, and not meant to run on every change — invoke
it by name, manually, only when asked:

    docker exec intact_backend python3 /app/workdir/tests/live/test_case_management.py
"""
import io
import json
import sys

import requests

from _lib import BASE, TIMEOUT, SAFE, Skip, _get, _post, _delete, tagged, require_module, \
    synthetic_cloudtrail_event, poll_run


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _produce_aws_run(suffix):
    """Upload + offline-analyze one synthetic CloudTrail event, return the
    completed run_id. Real multipart upload (see module docstring point 1)."""
    event = synthetic_cloudtrail_event(suffix)
    content = json.dumps({"Records": [event]}).encode()
    files = {"files": ("cloudtrail_test.json", io.BytesIO(content), "application/json")}
    up = requests.post(f"{BASE}/api/aws/upload", files=files, timeout=TIMEOUT)
    if up.status_code != 200:
        raise RuntimeError(f"POST /api/aws/upload -> {up.status_code}: {up.text[:300]}")
    run_id = up.json().get("run_id")
    if not run_id:
        raise RuntimeError(f"no run_id from upload: {up.text[:300]}")

    an = _post("/api/aws/analyze-offline", {"run_id": run_id, "min_severity": "informational"})
    if an.status_code != 200:
        raise RuntimeError(f"POST /api/aws/analyze-offline -> {an.status_code}: {an.text[:300]}")

    final, transitions = poll_run(run_id, timeout_seconds=60)
    if final.get("status") != "completed":
        raise RuntimeError(f"aws run {run_id} ended as '{final.get('status')}' (transitions: {transitions})")
    return run_id


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_case_full_lifecycle():
    require_module("aws_sigma")
    notes = []
    case_id = None
    imported_case_id = None
    try:
        # 1. create
        name = tagged("case")
        r = _post("/api/cases", {"name": name, "min_severity": "informational"})
        if r.status_code != 200:
            return False, f"POST /api/cases -> {r.status_code}: {r.text[:300]}"
        case_id = r.json().get("case_id")
        if not case_id:
            return False, f"no case_id in create response: {r.text[:300]}"

        # 2. synthetic AWS member run
        run_id = _produce_aws_run("lifecycle")

        # 2b. opt this case into "aws" fusion (see module docstring point 2) so the
        # rest of the flow has a real fused entity/finding to exercise.
        fm = _post(f"/api/cases/{case_id}/config", {"fusion_modules": ["velociraptor_agentic", "memory", "aws"]})
        if fm.status_code != 200:
            return False, f"POST .../config (fusion_modules) -> {fm.status_code}: {fm.text[:300]}"

        # 3. attach + fuse
        att = _post(f"/api/cases/{case_id}/attach", {"run_ids": [run_id], "fuse": True})
        if att.status_code != 200:
            return False, f"POST .../attach -> {att.status_code}: {att.text[:300]}"
        ab = att.json()
        if not ab.get("fused"):
            return False, f"attach did not report fused: {att.text[:300]}"
        if run_id not in (ab.get("member_run_ids") or []):
            return False, f"run_id not in member_run_ids after attach: {att.text[:300]}"
        notes.append(f"attach fused entities={ab.get('entities')} findings={ab.get('findings')}")

        # 4. get case, sanity
        g = _get(f"/api/cases/{case_id}")
        if g.status_code != 200:
            return False, f"GET /api/cases/{case_id} -> {g.status_code}: {g.text[:300]}"
        gd = g.json()
        if gd.get("case_id") != case_id or "counts" not in gd:
            return False, f"case shape looks wrong: {str(gd)[:300]}"

        # 5. config (a real field: widen the time window so it never accidentally
        # filters out our synthetic event) then rescan
        cfg = _post(f"/api/cases/{case_id}/config",
                    {"time_window": {"start": "2026-01-01T00:00:00Z", "end": "2026-12-31T00:00:00Z"}})
        if cfg.status_code != 200:
            return False, f"POST .../config -> {cfg.status_code}: {cfg.text[:300]}"

        rs = _post(f"/api/cases/{case_id}/rescan")
        if rs.status_code != 200:
            return False, f"POST .../rescan -> {rs.status_code}: {rs.text[:300]}"
        rsb = rs.json()
        if rsb.get("status") != "rescanned":
            return False, f"rescan didn't report rescanned: {rs.text[:300]}"
        notes.append(f"rescan entities={rsb.get('entities')} findings={rsb.get('findings')}")

        # 6. hosts
        hosts_r = _get(f"/api/cases/{case_id}/hosts")
        if hosts_r.status_code != 200:
            return False, f"GET .../hosts -> {hosts_r.status_code}: {hosts_r.text[:300]}"
        hosts_list = hosts_r.json().get("hosts")
        if not isinstance(hosts_list, list):
            return False, f"'hosts' missing or not a list: {str(hosts_r.json())[:300]}"
        notes.append(f"hosts={len(hosts_list)}")

        # 7. identities — degrade gracefully: single-provider (AWS-only) synthetic
        # data never produces a cross-infra candidate link (identity_view() requires
        # >=2 buckets for a "suggestion"), so this is expected, not a bug.
        idn_r = _get(f"/api/cases/{case_id}/identities")
        if idn_r.status_code != 200:
            return False, f"GET .../identities -> {idn_r.status_code}: {idn_r.text[:300]}"
        idn = idn_r.json()
        if "identities" not in idn or "buckets" not in idn:
            return False, f"identities response shape looks wrong: {str(idn)[:300]}"
        link_id = None
        for it in idn.get("identities") or []:
            for s in it.get("suggestions") or []:
                link_id = s.get("id")
                break
            if link_id:
                break
        if link_id:
            dec = _post(f"/api/cases/{case_id}/identities/{link_id}", {"decision": "confirmed"})
            if dec.status_code != 200:
                return False, f"POST .../identities/{link_id} -> {dec.status_code}: {dec.text[:300]}"
            undo = _post(f"/api/cases/{case_id}/identities/undo", {"id": link_id})
            if undo.status_code != 200:
                return False, f"POST .../identities/undo -> {undo.status_code}: {undo.text[:300]}"
            notes.append(f"identity link {link_id} confirm/undo round-trip OK")
        else:
            notes.append(f"identities: no candidate link (buckets={idn.get('buckets')}, "
                         f"multi_infra={idn.get('multi_infra')}) — expected for single-provider "
                         "synthetic data, not exercised")

        # 8. timeline: add manual event -> list -> delete
        ev = _post(f"/api/cases/{case_id}/timeline/event", {"title": tagged("event")})
        if ev.status_code != 200:
            return False, f"POST .../timeline/event -> {ev.status_code}: {ev.text[:300]}"
        event_id = (ev.json().get("event") or {}).get("finding_id")
        if not event_id:
            return False, f"no event finding_id in response: {ev.text[:300]}"

        tl = _get(f"/api/cases/{case_id}/timeline")
        if tl.status_code != 200:
            return False, f"GET .../timeline -> {tl.status_code}: {tl.text[:300]}"
        rows = tl.json().get("timeline") or []
        if not any(row.get("finding_id") == event_id for row in rows):
            return False, f"manual event {event_id} not present in timeline ({len(rows)} rows)"

        del_ev = _delete(f"/api/cases/{case_id}/timeline/event/{event_id}")
        if del_ev.status_code != 200:
            return False, f"DELETE .../timeline/event/{event_id} -> {del_ev.status_code}: {del_ev.text[:300]}"
        notes.append(f"timeline event {event_id} add/list/delete round-trip OK")

        # 9. checklist — decline is the least-state-changing valid decision (accept
        # triggers a disposition + re-fuse; decline just records the answer).
        cl = _get(f"/api/cases/{case_id}/checklist")
        if cl.status_code != 200:
            return False, f"GET .../checklist -> {cl.status_code}: {cl.text[:300]}"
        items = cl.json().get("checklist") or []
        if items:
            item_id = items[0]["id"]
            dec = _post(f"/api/cases/{case_id}/checklist/{item_id}", {"decision": "decline"})
            if dec.status_code != 200:
                return False, f"POST .../checklist/{item_id} -> {dec.status_code}: {dec.text[:300]}"
            if dec.json().get("status") != "declined":
                return False, f"checklist decision didn't round-trip: {dec.text[:300]}"
            notes.append(f"checklist item {item_id} decline round-trip OK")
        else:
            notes.append("checklist empty — no benign-suggestion candidates from this synthetic data")

        # 10. branding -> report (explicit use_llm:false, deterministic narrator,
        # never depends on an LLM key) -> markdown download -> pdf download (best-effort)
        br = _post(f"/api/cases/{case_id}/branding", {"customer_name": tagged("cust"), "tlp": "AMBER"})
        if br.status_code != 200:
            return False, f"POST .../branding -> {br.status_code}: {br.text[:300]}"

        rep = _post(f"/api/cases/{case_id}/report", {"use_llm": False})
        if rep.status_code != 200:
            return False, f"POST .../report -> {rep.status_code}: {rep.text[:300]}"
        if "report_md" not in rep.json():
            return False, f"report response missing report_md: {rep.text[:300]}"

        dl = _get(f"/api/cases/{case_id}/report/download")
        if dl.status_code != 200:
            return False, f"GET .../report/download -> {dl.status_code}: {dl.text[:300]}"
        if len(dl.content) < 20:
            return False, f"report download body suspiciously small: {len(dl.content)} bytes"
        notes.append(f"report md download {len(dl.content)} bytes")

        # PDF: a missing renderer dependency (e.g. WeasyPrint) is a documented 503
        # ({"error": "pdf render failed: ..."}) per report_download_pdf()'s broad
        # except -> jsonify. Treat that specific shape as a soft-skip, not a fail.
        pdf = requests.get(f"{BASE}/api/cases/{case_id}/report/download/pdf", timeout=TIMEOUT)
        if pdf.status_code == 200:
            if len(pdf.content) < 100:
                return False, f"pdf download returned suspiciously small body: {len(pdf.content)} bytes"
            notes.append(f"report pdf download {len(pdf.content)} bytes")
        elif pdf.status_code == 503:
            err = ""
            try:
                err = (pdf.json().get("error") or "")
            except Exception:
                pass
            if "pdf render failed" in err:
                notes.append(f"report pdf download SKIPPED (renderer unavailable: {err[:150]})")
            else:
                return False, f"pdf download 503 with unexpected error: {err[:300]}"
        else:
            return False, f"GET .../report/download/pdf -> {pdf.status_code}: {pdf.text[:300]}"

        # 11. graph / analysis / dispositions / metrics — pure reads
        gr = _get(f"/api/cases/{case_id}/graph")
        if gr.status_code != 200:
            return False, f"GET .../graph -> {gr.status_code}: {gr.text[:300]}"
        fg = gr.json().get("fusion_graph") or {}
        findings = fg.get("findings") or []
        if "entities" not in fg:
            return False, f"graph response missing fusion_graph.entities: {str(gr.json())[:300]}"

        an = _get(f"/api/cases/{case_id}/analysis")
        if an.status_code != 200 or "analysis" not in an.json():
            return False, f"GET .../analysis -> {an.status_code}: {an.text[:300]}"

        dp = _get(f"/api/cases/{case_id}/dispositions")
        if dp.status_code != 200 or "dispositions" not in dp.json():
            return False, f"GET .../dispositions -> {dp.status_code}: {dp.text[:300]}"

        mt = _get(f"/api/cases/{case_id}/metrics")
        if mt.status_code != 200 or "llm_enabled" not in mt.json():
            return False, f"GET .../metrics -> {mt.status_code}: {mt.text[:300]}"
        notes.append(f"graph/analysis/dispositions/metrics reads OK (findings={len(findings)})")

        # 12. disposition — only if the fused graph actually produced a finding
        if findings:
            fid = findings[0]["id"]
            ds = _post(f"/api/cases/{case_id}/disposition",
                       {"target": fid, "verdict": "benign", "attribution": "operator",
                        "reason": "_livetest_ disposition", "scope": "case"})
            if ds.status_code != 200:
                return False, f"POST .../disposition -> {ds.status_code}: {ds.text[:300]}"
            notes.append(f"disposition applied to finding {fid}")
        else:
            notes.append("no findings in fused graph — disposition sub-step SKIPPED "
                         "(zero findings from one synthetic low-severity event is expected)")

        # 13. export -> import (name override) -> confirm visible in GET /api/cases
        exp = _get(f"/api/cases/{case_id}/export")
        if exp.status_code != 200:
            return False, f"GET .../export -> {exp.status_code}: {exp.text[:300]}"
        export_bytes = exp.content
        if len(export_bytes) < 20:
            return False, f"export body suspiciously small: {len(export_bytes)} bytes"

        imp_files = {"file": ("export.json", io.BytesIO(export_bytes), "application/json")}
        imp = requests.post(f"{BASE}/api/cases/import", files=imp_files,
                            data={"name": tagged("case-imported")}, timeout=TIMEOUT)
        if imp.status_code != 200:
            return False, f"POST /api/cases/import -> {imp.status_code}: {imp.text[:300]}"
        imported_case_id = imp.json().get("case_id")
        if not imported_case_id:
            return False, f"no case_id in import response: {imp.text[:300]}"

        lst = _get("/api/cases")
        if lst.status_code != 200:
            return False, f"GET /api/cases -> {lst.status_code}: {lst.text[:300]}"
        ids = [c.get("case_id") for c in (lst.json().get("cases") or [])]
        if imported_case_id not in ids:
            return False, f"imported case {imported_case_id} not visible in GET /api/cases"
        notes.append(f"export/import round-trip OK (imported case_id={imported_case_id})")

        return True, "; ".join(notes)
    finally:
        for cid in (case_id, imported_case_id):
            if cid:
                try:
                    _delete(f"/api/cases/{cid}")
                except Exception:
                    pass


def check_case_quick_create():
    require_module("aws_sigma")
    case_id = None
    try:
        run_id = _produce_aws_run("quick")
        r = _post("/api/cases/quick", {"name": tagged("case-quick"), "run_ids": [run_id],
                                       "min_severity": "informational"})
        if r.status_code != 200:
            return False, f"POST /api/cases/quick -> {r.status_code}: {r.text[:300]}"
        b = r.json()
        case_id = b.get("case_id")
        if not case_id:
            return False, f"no case_id in quick-create response: {r.text[:300]}"
        if b.get("status") != "fused":
            return False, f"quick-create didn't report fused: {r.text[:300]}"
        if "report_md" not in b:
            return False, f"quick-create response missing report_md: {r.text[:300]}"
        # /api/cases/quick has no fusion_modules param (confirmed by reading
        # case_routes.py's quick_case()) — an all-AWS run always fuses under the
        # velociraptor_agentic+memory DEFAULT here, so 0 entities/findings is the
        # expected, correct outcome for this synthetic input, not a bug.
        return True, (f"case_id={case_id} entities={b.get('entities')} "
                      f"findings={b.get('findings')} report_md_len={len(b.get('report_md') or '')}")
    finally:
        if case_id:
            try:
                _delete(f"/api/cases/{case_id}")
            except Exception:
                pass


CHECKS = [
    ("case_full_lifecycle", SAFE, check_case_full_lifecycle),
    ("case_quick_create", SAFE, check_case_quick_create),
]


def main():
    passed = failed = skipped = 0
    for name, risk, fn in CHECKS:
        print(f"\n--- {name} ---", flush=True)
        try:
            if risk.startswith("REQUIRES_MODULE:"):
                require_module(risk.split(":", 1)[1])
            ok, detail = fn()
        except Skip as e:
            print(f"[SKIP] {name}: {e}", flush=True)
            skipped += 1
            continue
        except Exception as e:
            ok, detail = False, f"unhandled exception: {e}"
        shown = detail if len(detail) <= 300 else detail[:300] + "... [truncated]"
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: {shown}", flush=True)
        if ok:
            passed += 1
        else:
            failed += 1

    print(f"\n=== {passed} passed, {failed} failed, {skipped} skipped ===", flush=True)
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
