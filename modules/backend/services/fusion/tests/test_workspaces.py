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


def test_members_are_tag_based():
    cid = store.create_case("ws-test-members")
    rid = ws.create_automation_run("agentic", "tagged run", details={"client_name": "H"},
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
