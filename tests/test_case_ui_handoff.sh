#!/bin/bash
# Export and Import must behave the SAME way: a button in Case Management that
# starts a System action and hands the operator to Settings -> Actions.
#
# This is a static test on purpose. The bug it guards against was not a broken
# function -- it was two flows that drifted apart, one navigating and the other
# growing its own inline progress UI that duplicated (badly) what Settings ->
# Actions already does. Nothing at runtime notices that kind of divergence.
set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.."
HTML=modules/nginx/html
CASES=$HTML/cases.html
AC=$HTML/js/active-case.js
fail=0
ok(){ echo "  ok: $1"; }
bad(){ echo "  FAIL: $1"; fail=1; }

echo "=== both entry points live in Case Management ==="
grep -q "onclick=\"exportWorkspace(" $CASES && ok "Export button on the case row" || bad "no Export button"
grep -q "onchange=\"importWorkspace(event)\"" $CASES && ok "Import button in the Cases header" || bad "no Import button"

echo "=== both hand off to Settings -> Actions ==="
for fn in exportWorkspace importWorkspace; do
  body=$(awk "/^function $fn\(/,/^}/" $CASES)
  echo "$body" | grep -q "gotoSystemWorkflows" \
    && ok "$fn hands off to Settings -> Actions" \
    || bad "$fn does not hand off to Settings -> Actions"
done

echo "=== neither grows its own progress UI ==="
# The whole point of the hand-off: the run row is the one place progress lives.
for token in impPanel resolveImportRun watchImport 'exports_\[' staleExportBar; do
  grep -q "$token" $CASES && bad "cases.html still carries inline progress ($token)" \
                          || ok "no inline progress: $token"
done

echo "=== the hand-off works from inside the Cases iframe ==="
grep -q "window.top" $AC && ok "gotoSystemWorkflows walks up to the top window" \
                         || bad "gotoSystemWorkflows would switch a tab nobody can see"
grep -q "top.CustomEvent" $AC && ok "the event is built in the target realm" \
                              || bad "cross-realm event construction"

echo "=== Settings -> Actions can actually show what arrives ==="
grep -q "show-system-actions.window" $HTML/partials/settings.html \
  && ok "settings listens for the hand-off" || bad "no listener in settings"
for p in partials/settings.html partials/workflows.html; do
  grep -q "case_export" $HTML/$p && ok "$p offers the bundle download" \
                                 || bad "$p has no case_export download"
done

echo "=== the import opens exactly one run row ==="
# The browser must NOT pre-create a run: when its id failed to reach the upload
# hook, the hook opened a second row and the first stranded at PENDING forever.
grep -q "cases/import/start" $CASES && bad "the browser still pre-creates an import run" \
                                    || ok "the upload hook owns the run row"
grep -q "workflow_type = 'case_import'" modules/backend/routes/upload_routes.py \
  && ok "a case-bundle upload is typed case_import, not case_import_upload" \
  || bad "the upload row is typed separately from the import"

echo
[ $fail -eq 0 ] && echo "PASS" || echo "FAILED"
exit $fail
