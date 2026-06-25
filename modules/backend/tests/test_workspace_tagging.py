"""Workspace-tagging tests for workflow_service._resolve_case_id.

The universal rule (the fix for runs vanishing from the Workflows view):
  - SYSTEM_TYPES                 -> the System workspace, always
  - everything else (a module)   -> the ACTIVE workspace:
        explicit case_id  >  request's active case (X-Case-Id)  >  Default
  - a module may NOT run in the System workspace -> WorkspaceError

Before the fix, any run type that was neither system nor on the AGENTIC_TYPES
allow-list (e.g. velociraptor_offline_collector) fell through to case_id=None and
was invisible in every workspace-scoped view. These tests lock the new behavior in.

Run:  docker exec intact_backend python -m pytest /app/tests/test_workspace_tagging.py -v
  or: docker exec intact_backend python /app/tests/test_workspace_tagging.py
"""

import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

import services.workflow_service as ws   # noqa: E402

SYS = "case_SYSTEM"
ACTIVE = "case_ACTIVE"
DEFAULT = "case_DEFAULT"


class _env:
    """Patch the workspace lookups around a block, then restore. Lets each test
    pin the System id, the request's active case, and the Default cache."""
    def __init__(self, active=None, system=SYS, default=DEFAULT):
        self.active, self.system, self.default = active, system, default

    def __enter__(self):
        self._saved = (ws._system_case_id, ws._active_case_from_request,
                       dict(ws._DEFAULT_CASE_CACHE))
        ws._system_case_id = lambda: self.system
        ws._active_case_from_request = lambda: self.active
        ws._DEFAULT_CASE_CACHE["id"] = self.default
        return self

    def __exit__(self, *a):
        ws._system_case_id, ws._active_case_from_request, cache = self._saved
        ws._DEFAULT_CASE_CACHE.clear(); ws._DEFAULT_CASE_CACHE.update(cache)


def _a_system_type():
    return sorted(ws.SYSTEM_TYPES)[0]


def test_system_type_always_goes_to_system_workspace():
    with _env(active=ACTIVE):
        # Even with a different active workspace, a system op lands in System.
        assert ws._resolve_case_id(_a_system_type(), None) == SYS


def test_module_with_active_case_goes_to_active():
    with _env(active=ACTIVE):
        assert ws._resolve_case_id("velociraptor_offline_collector", None) == ACTIVE


def test_module_explicit_case_id_wins_over_active():
    with _env(active=ACTIVE):
        assert ws._resolve_case_id("velociraptor_offline_collector", "case_EXPLICIT") == "case_EXPLICIT"


def test_module_with_no_active_case_falls_back_to_default():
    with _env(active=None):
        assert ws._resolve_case_id("velociraptor_offline_collector", None) == DEFAULT


def test_module_in_system_workspace_is_rejected():
    # Active workspace IS the System workspace -> a module must not run there.
    raised = False
    with _env(active=SYS):
        try:
            ws._resolve_case_id("velociraptor_offline_collector", None)
        except ws.WorkspaceError:
            raised = True
    assert raised, "expected WorkspaceError when a module runs in the System workspace"


def test_offline_collector_no_longer_becomes_untagged():
    # Regression for the actual bug: this used to return None (invisible everywhere).
    with _env(active=ACTIVE):
        assert ws._resolve_case_id("velociraptor_offline_collector", None) is not None


def test_offline_import_also_tagged():
    with _env(active=ACTIVE):
        assert ws._resolve_case_id("velociraptor_offline_import", None) == ACTIVE


def test_brand_new_unknown_type_is_still_tagged():
    # A future module nobody added to any list still gets the active workspace.
    with _env(active=ACTIVE):
        assert ws._resolve_case_id("some_future_module_2027", None) == ACTIVE


def test_system_type_without_resolvable_system_case_falls_back_to_case_id():
    with _env(active=ACTIVE, system=None):
        assert ws._resolve_case_id(_a_system_type(), "explicit") == "explicit"


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1; print(f"FAIL {fn.__name__}"); traceback.print_exc()
    print(f"\n{len(fns)-failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
