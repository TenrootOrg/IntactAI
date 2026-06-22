"""Unified timeline: source artifact per row, reversible 4-state validation
(real / not_real / known_it / pending), and operator-added manual events.
"""

import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.fusion import store, calibrate, render  # noqa: E402
from services.fusion.schema import FusionGraph, Entity, Finding, EvidenceRef  # noqa: E402


def test_timeline_row_carries_source_artifact():
    # The artifact that produced a finding comes from its evidence locator
    # ("Windows.Hayabusa.Rules/row=3") so the analyst can ask the IT team.
    g = FusionGraph(case_id="c")
    g.upsert(Entity(id="asset:endpoint:C.a", type="asset", label="DC01",
                    attrs={"_assets": ["asset:endpoint:C.a"]}))
    g.add_finding(Finding(
        id="f_x", title="SIGMA: Defender Alert (Severe)", severity="high",
        confidence="high", summary="...", asset_ids=["asset:endpoint:C.a"],
        ts="2026-06-07T09:33:19",
        evidence=[EvidenceRef("velociraptor", "r1", "Windows.Hayabusa.Rules/row=3")]))
    rows = render.timeline(g)
    assert rows and rows[0]["artifacts"] == ["Windows.Hayabusa.Rules"]
    assert rows[0]["source"] == "fusion"


def _fresh_case():
    # A case with a REAL member run (not a contributions_override) so that the
    # re-fuse triggered by validate_timeline rebuilds the same graph from members.
    from services import workflow_service as ws
    for r in ws.get_all_automation_runs() or []:
        d = r.get("details") or {}
        if (r.get("automation_type") == store.CASE_TYPE and d.get("name") == "timeline-test") \
                or r.get("name") == "timeline-test-run":
            try:
                store.delete_case(r.get("run_id"))
            except Exception:
                pass
    cd = {"Windows.Hayabusa.Rules": [
        {"_client_id": "C.a", "_hostname": "DC01", "Computer": "DC01",
         "Timestamp": "2026-06-07T09:33:19Z", "Level": "high",
         "RuleTitle": "Defender Alert (Severe)",
         "Channel": "Microsoft-Windows-Windows Defender/Operational",
         "EventID": "1116", "RecordID": "5"}]}
    rid = ws.create_automation_run("agentic", "timeline-test-run",
                                   {"collected_data": cd, "hostnames": {"C.a": "DC01"}})
    cid = store.create_case("timeline-test", min_severity="low", member_run_ids=[rid])
    store.fuse_case(cid)
    return cid


def _suppressible_row(cid):
    # a non-critical finding (critical is never silently suppressed)
    for r in store.get_timeline(cid):
        if not r.get("manual") and r["severity"] in ("high", "medium", "low"):
            return r
    return None


def test_validate_timeline_is_reversible():
    cid = _fresh_case()
    row = _suppressible_row(cid)
    assert row, "fixture should yield a suppressible finding"
    fid, sev0 = row["finding_id"], row["severity"]

    def sev_now():
        r = next((x for x in store.get_timeline(cid) if x["finding_id"] == fid), None)
        return r and r["severity"], r and r["validation"]

    store.validate_timeline(cid, fid, "not_real")
    assert sev_now() == ("informational", "not_real"), "not_real suppresses"

    store.validate_timeline(cid, fid, "real")
    assert sev_now() == (sev0, "real"), "real un-suppresses (restores severity)"

    store.validate_timeline(cid, fid, "known_it", "IT confirmed")
    assert sev_now() == ("informational", "known_it"), "known_it suppresses"

    store.validate_timeline(cid, fid, "pending")
    assert sev_now() == (sev0, "pending"), "pending un-suppresses + clears the record"
    store.delete_case(cid)


def test_manual_timeline_event_lifecycle():
    cid = _fresh_case()
    ev = store.add_manual_timeline_event(
        cid, {"ts": "2026-06-20T10:00:00", "host": "ALDC02",
              "title": "IT pushed a GPO", "severity": "low", "description": "change window"})
    fid = ev["finding_id"]
    assert fid.startswith("manual:")
    row = next((x for x in store.get_timeline(cid) if x["finding_id"] == fid), None)
    assert row and row["manual"] is True and row["validation"] == "real"
    assert row["artifacts"] == ["manual"] and row["source"] == "manual"

    store.validate_timeline(cid, fid, "known_it", "scheduled")
    row = next((x for x in store.get_timeline(cid) if x["finding_id"] == fid), None)
    assert row["validation"] == "known_it" and row["notes"] == "scheduled"

    store.delete_manual_timeline_event(cid, fid)
    assert not any(x["finding_id"] == fid for x in store.get_timeline(cid))
    store.delete_case(cid)
