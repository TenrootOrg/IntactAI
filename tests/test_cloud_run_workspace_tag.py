"""An uploaded cloud run must be tagged to a workspace at creation.

THE BUG THIS EXISTS FOR. `/api/aws/upload` and `/api/azure/upload` built their
workflow row by calling `save_workflow()` directly, and the dict they passed had
no `case_id`. `save_workflow` writes the value verbatim, so the row landed with
case_id NULL. Every later read goes through
`_run_visible_in_active_workspace()` (aws_routes.py), which returns False when
the row's case_id does not match the request's active case -- so
`/api/aws/status/<run_id>` answered **404 to the very operator who had just
uploaded the file**, before any restart was involved.

Measured in e2e run 34203567795: POST /api/aws/upload -> 200, POST
/api/aws/analyze-offline -> 200, then GET /api/aws/status/<id> -> 404 on every
poll for 180 s.

Why it looked fine on a live box: `reassign_null_case()` backfills NULL rows,
but only ONCE per process (`_BOOTSTRAP_DONE` in case_routes.py) and only to the
DEFAULT workspace. A row created after that first request is never backfilled,
and a row created while a non-default case is active is tagged to the wrong one.

The fix is to use `_resolve_case_id()`, which workflow_service.py:126 calls "ONE
universal rule so no module/feature can silently fall through and become
invisible in the workspace-scoped views" -- exactly what these two handlers were
bypassing. `velociraptor_routes.py` already imports it the same way.

AST rather than grep: this asserts the key is really in the dict passed to
save_workflow, not merely that the string appears somewhere in the file.
"""

import ast
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROUTES = {
    "aws": os.path.join(ROOT, "modules/backend/routes/aws_routes.py"),
    "azure": os.path.join(ROOT, "modules/backend/routes/azure_routes.py"),
}


def _save_workflow_calls(path):
    """Every `save_workflow({...})` call in the file, as its literal key set."""
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        name = getattr(fn, "id", None) or getattr(fn, "attr", None)
        if name != "save_workflow" or not node.args:
            continue
        arg = node.args[0]
        if isinstance(arg, ast.Dict):
            out.append({k.value for k in arg.keys
                        if isinstance(k, ast.Constant) and isinstance(k.value, str)})
    return out


class TestUploadedCloudRunsAreTaggedToAWorkspace(unittest.TestCase):
    def test_every_save_workflow_literal_carries_a_case_id(self):
        for provider, path in ROUTES.items():
            calls = _save_workflow_calls(path)
            with self.subTest(provider=provider):
                self.assertTrue(calls, f"no save_workflow({{...}}) found in {path} "
                                       "-- the call moved, update this test")
                for keys in calls:
                    self.assertIn(
                        "case_id", keys,
                        f"{provider} builds a workflow row without case_id: the row "
                        "lands NULL and the status route 404s to its own creator")

    def test_the_tag_comes_from_the_universal_resolver(self):
        # Not a hand-rolled `g.case_id` read: _resolve_case_id also handles the
        # System-workspace redirect and the no-request (scheduler) fallback.
        for provider, path in ROUTES.items():
            with open(path, encoding="utf-8") as fh:
                src = fh.read()
            with self.subTest(provider=provider):
                self.assertIn("_resolve_case_id", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
