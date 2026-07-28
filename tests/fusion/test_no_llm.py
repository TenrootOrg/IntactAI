"""No-LLM mode guarantees — the product must work with NO API key.

Covers the data-layer contracts: is_llm_configured truth table, the agentic
file-fallback that makes a REAL (file-persisted) agentic run fuseable, and the
collect-only report. The fusion keyless paths are covered by test_llm_contract.
"""

import sys
import os
import json
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.agentic.analyzers import is_llm_configured  # noqa: E402
from services.fusion import store  # noqa: E402


def test_is_llm_configured_truth_table():
    assert is_llm_configured({}) is False
    assert is_llm_configured({"agentic": {"llm_mode": "online", "online_llm": {}}}) is False
    assert is_llm_configured(
        {"agentic": {"llm_mode": "online", "online_llm": {"api_key": "k"}}}) is True
    assert is_llm_configured(
        {"agentic": {"llm_mode": "offline", "offline_llm": {"url": "http://o"}}}) is True
    assert is_llm_configured(
        {"agentic": {"llm_mode": "offline", "offline_llm": {}}}) is False


def test_agentic_run_fuseable_from_raw_results_file():
    # The real pipeline writes rows to /data/downloads/<rid>/raw_results.json (NOT details).
    # store must read that so a real agentic run fuses.
    rid = "agentic_nolltest_1"
    rows = {"Generic.System.Pstree": [
        {"Pid": 10, "Ppid": 4, "Name": "evil.exe", "CreateTime": "2026-06-15T08:00:00Z",
         "_client_id": "C.z", "_hostname": "H"}]}
    for base in ("/data/downloads", "/app/data/downloads"):
        try:
            os.makedirs(f"{base}/{rid}", exist_ok=True)
            with open(f"{base}/{rid}/raw_results.json", "w") as f:
                json.dump(rows, f)
            break
        except Exception:
            continue
    det = {"hostnames": {"C.z": "H"}}                 # NO collected_data in details
    cd = store._agentic_collected_data(rid, det)
    assert cd and "Generic.System.Pstree" in cd, "must fall back to the raw_results.json file"
    # and it maps to entities (fuseable)
    ents, _ = store.map_agentic(cd, run_id=rid, hostnames={"C.z": "H"})
    assert any(e.type == "process" for e in ents), "file-based agentic run must be fuseable"


def test_offline_upload_run_is_a_fusion_member_type():
    # The offline-collector upload auto-collects into its OWN row (one workflow,
    # not two), so that row's type must be a case/fusion member.
    from services import workflow_service as ws
    assert "velociraptor_upload" in ws.AGENTIC_TYPES


def test_offline_upload_run_fuses_like_an_agentic_run():
    # An offline-collector upload run (atype velociraptor_upload) persists rows
    # the same way and must contribute the same entities as an agentic run —
    # via the same map_agentic dispatch in _contribution_for_run.
    rid = "velo_upload_nolltest_1"
    rows = {"Generic.System.Pstree": [
        {"Pid": 11, "Ppid": 4, "Name": "evil.exe", "CreateTime": "2026-06-15T08:00:00Z",
         "_client_id": "C.up", "_hostname": "ADATUM"}]}
    for base in ("/data/downloads", "/app/data/downloads"):
        try:
            os.makedirs(f"{base}/{rid}", exist_ok=True)
            with open(f"{base}/{rid}/raw_results.json", "w") as f:
                json.dump(rows, f)
            break
        except Exception:
            continue
    run = {"run_id": rid, "automation_type": "velociraptor_upload",
           "details": {"hostnames": {"C.up": "ADATUM"}}}
    ents, _ = store._contribution_for_run(run)
    assert any(e.type == "process" for e in ents), \
        "velociraptor_upload run must fuse via the agentic mapper"
    assert any(e.type == "asset" and "adatum" in str(e.label).lower() for e in ents), \
        "host card must show the seeded hostname"


def test_agentic_details_collected_data_takes_precedence():
    det = {"collected_data": {"X": [{"_client_id": "C.z", "_hostname": "H"}]}}
    assert store._agentic_collected_data("nope_rid", det) == det["collected_data"]


def test_collect_only_report_is_informative():
    from services.agentic.pipeline import _collect_only_report
    md = _collect_only_report(120, {"Windows.Hayabusa.Rules": [], "Generic.System.Pstree": []}, 3)
    # Assert the contract the function documents — states what was collected
    # and points the operator at fusion — not a literal heading. This required
    # the phrase "collection-only", which the report has never used; the
    # shipped wording is "Collection complete", and it is the better wording.
    assert "120 rows" in md and "3 client(s)" in md      # what was collected
    assert "Hayabusa" in md and "Pstree" in md           # lists the artifacts
    assert "case" in md.lower() and "fuse" in md.lower()  # points at fusion


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    p = f = 0
    for fn in fns:
        try:
            fn(); p += 1; print(f"PASS {fn.__name__}")
        except AssertionError as e:
            f += 1; print(f"FAIL {fn.__name__}: {e}")
    print(f"{p}/{len(fns)} passed")
    sys.exit(1 if f else 0)
