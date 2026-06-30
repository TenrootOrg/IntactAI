"""Workspace store invariants — Default bootstrap, delete cascade + guard, tag-based membership.
Data-layer counterpart to the HTTP suite at /home/tenroot/tests/suites/11_workspaces.py.
"""

import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services import workflow_service as ws  # noqa: E402
from services.fusion import store, calibrate  # noqa: E402


def test_ensure_default_case_is_idempotent():
    a = store.ensure_default_case()
    b = store.ensure_default_case()
    assert a == b, "ensure_default_case must return the same id (no duplicate Default)"
    assert store.is_default_case(a), "the returned case must be flagged default"


def test_default_case_cannot_be_deleted():
    did = store.ensure_default_case()
    res = store.delete_case(did)
    assert res.get("deleted") is False and "default" in (res.get("error") or "").lower()
    assert store.get_case(did), "Default must still exist after a refused delete"


def test_ensure_system_case_is_idempotent_and_undeletable():
    a = store.ensure_system_case()
    b = store.ensure_system_case()
    assert a == b, "ensure_system_case must return the same id (no duplicate System)"
    assert store.is_system_case(a) and not store.is_default_case(a)
    res = store.delete_case(a)
    assert res.get("deleted") is False and "system" in (res.get("error") or "").lower()
    assert store.get_case(a), "System must still exist after a refused delete"


def test_system_run_types_route_to_system_workspace():
    sysid = store.ensure_system_case()
    rid = ws.create_automation_run("maintenance", "sys run", details={})
    from services.file_storage_service import get_workflow
    assert get_workflow(rid).get("case_id") == sysid, \
        "a system-type run must tag to the System workspace regardless of active case"
    from services.storage.workflow_store import delete_workflow
    delete_workflow(rid)


def test_checklist_is_grounded_to_real_findings():
    from services.fusion import llm_sim
    g = calibrate.fuse("attack2")
    cl = llm_sim.generate_disposition_checklist(g, min_severity="informational")
    valid = {f.id for f in g.findings}
    assert cl, "expected checklist items for the attack2 fixture"
    assert all(it.get("finding_id") in valid for it in cl), \
        "every checklist item must cite a real finding_id"


def test_masked_report_anonymizes_host_labels():
    # New semantics: masking anonymizes identifiers IN TRANSIT to the LLM, then
    # REVERTS in the output (the operator's report is real). So host labels must be
    # gone from the masked LLM INPUT, and restored by revert.
    import json
    from services.fusion import llm_sim, render
    from services.data_anonymizer import DataAnonymizer
    g = calibrate.fuse("attack2")
    hosts = [e.label for e in g.entities.values() if e.type == "asset" and e.label]
    assert hosts, "fixture should have host assets"
    mask = DataAnonymizer()
    llm_sim._build_mask_mapping(g, mask)
    raw = json.dumps(render.distilled(g))
    present = [h for h in hosts if h in raw]          # distilled() trims to top entities
    assert present, "some host labels should be in the distilled payload"
    masked_input = llm_sim._apply_mask(raw, mask)
    assert all(h not in masked_input for h in present), "host labels must be masked in the LLM input"
    reverted = llm_sim._revert_mask(masked_input, mask)
    assert all(h in reverted for h in present), "revert restores hosts"


def test_multi_run_case_merges_all_runs():
    """A case fuses EVERY run tagged to it (guards the 'can't merge multiple' misconception)."""
    cid = store.create_case("ws-multi", min_severity="informational")
    cd1 = {"Windows.System.Pslist": [{"Hostname": "HOST-A", "Pid": 11, "Name": "a.exe"}]}
    cd2 = {"Windows.System.Pslist": [{"Hostname": "HOST-B", "Pid": 22, "Name": "b.exe"}]}
    ws.create_automation_run("velociraptor_collection", "r1",
                             details={"client_name": "HOST-A", "collected_data": cd1,
                                      "hostnames": {}}, case_id=cid)
    ws.create_automation_run("velociraptor_collection", "r2",
                             details={"client_name": "HOST-B", "collected_data": cd2,
                                      "hostnames": {}}, case_id=cid)
    g = store.fuse_case(cid)
    labels = " ".join((e.label or "") for e in g.entities.values()).upper()
    assert "HOST-A" in labels and "HOST-B" in labels, \
        "both tagged runs must appear in the fused graph"
    store.delete_case(cid)


def test_members_are_tag_based():
    cid = store.create_case("ws-test-members")
    rid = ws.create_automation_run("velociraptor_collection", "tagged run", details={"client_name": "H"},
                                   case_id=cid)
    members = store._members_for_case(cid)
    assert rid in members, "a run tagged with case_id must be a member without manual attach"
    store.delete_case(cid)


def test_delete_case_cascades_to_runs():
    cid = store.create_case("ws-test-delete")
    rid = ws.create_automation_run("memory", "tagged run", details={"client_name": "H"},
                                   case_id=cid)
    assert ws.get_automation_run(rid)
    res = store.delete_case(cid)
    assert res.get("deleted") and res.get("runs_deleted", 0) >= 1
    assert not ws.get_automation_run(rid), "the tagged run must be deleted with the workspace"
    assert not store.get_case(cid), "the case row must be gone"


def test_tag_based_fusion_non_empty():
    cid = store.create_case("ws-test-fuse", min_severity="informational")
    # reuse a real fixture contribution but routed through the tag-based path
    contrib = calibrate._contribution(calibrate.load_fixture("attack2"))
    g = store.fuse_case(cid, contributions_override=[contrib])
    assert len(g.entities) > 0 and len(g.findings) > 0
    store.delete_case(cid)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    p = f = 0
    for fn in fns:
        try:
            fn(); p += 1; print(f"PASS {fn.__name__}")
        except AssertionError as e:
            f += 1; print(f"FAIL {fn.__name__}: {e}")
        except Exception as e:
            f += 1; print(f"ERR  {fn.__name__}: {type(e).__name__}: {e}")
    print(f"{p}/{len(fns)} passed")
    sys.exit(1 if f else 0)
