"""Every backend route has a deliberate role in services/access_policy.POLICY.

A route left out of POLICY needs SUPERADMIN (fail closed), so nothing breaks
open -- but it also means a new route silently works for nobody below the
Super-admin, or someone "fixes" that by guessing. This finds every route with
ast (flask is a container dependency, so nothing here imports a route file)
and fails on: an authenticated endpoint missing from POLICY, a POLICY key that
names no route (stale after a rename), a {method: role} value missing one of
the route's methods, and a GET-only endpoint at SUPERADMIN that is not in
GET_SUPERADMIN below -- the lazy default a missing decision would look like.
"""
import ast
import glob
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, "modules", "backend")
for _p in (os.path.join(ROOT, "tests"), BACKEND):
    if _p not in sys.path:
        sys.path.insert(0, _p)

_BASE = tempfile.mkdtemp(prefix="intact-policytest-")
os.environ["INTACT_STORAGE_BASE"] = _BASE
os.environ["INTACT_AUTH_DIR"] = os.path.join(_BASE, "auth")
os.environ["INTACT_CONFIG_PATH"] = os.path.join(_BASE, "config.yaml")
import atexit  # noqa: E402
atexit.register(shutil.rmtree, _BASE, True)

import _optional_deps  # noqa: F401,E402
from services import access_policy  # noqa: E402
from services.users import ROLES, SUPERADMIN  # noqa: E402

# GET-only endpoints that really are Super-admin's: each shows host internals
# or the data of a Super-admin-only action. Add one only with that reason.
GET_SUPERADMIN = {
    "maintenance.list_purge_sections",       # sizes for the purge screen
    "system.data_location_get",              # host paths, last data move
    "system.data_location_disks",            # host mounts
    "upgrade.get_upgrade_quota",
    "upgrade.download_prepared_package",
    "upgrade.get_active_upgrade_run",        # upgrade log with host detail
    "support_bundle.download_support_bundle",
    "support_bundle.system_logs_list",       # docker logs of every container
    "support_bundle.system_log_read",
    "support_bundle.system_log_download",
    "db.export_database",                    # every case and setting
    "db.backup_database",
}


def exempt_paths():
    """auth_service.EXEMPT_PATHS, read from source: importing auth_service
    pulls in werkzeug, which is not here outside the container."""
    with open(os.path.join(BACKEND, "services", "auth_service.py")) as f:
        tree = ast.parse(f.read())
    for node in tree.body:
        if (isinstance(node, ast.Assign)
                and any(getattr(t, "id", None) == "EXEMPT_PATHS" for t in node.targets)):
            return set(ast.literal_eval(node.value.args[0]))
    raise AssertionError("EXEMPT_PATHS not found in auth_service.py")


def find_routes():
    """{endpoint: {"methods": set, "paths": set, "where": "file:line"}} for
    every @<bp>.route / @app.route in routes/*.py and app.py. The endpoint is
    what Flask puts in request.endpoint: "<Blueprint name>.<function>", or the
    bare function name for app.route."""
    files = sorted(glob.glob(os.path.join(BACKEND, "routes", "*.py")))
    files.append(os.path.join(BACKEND, "app.py"))
    found = {}
    for path in files:
        with open(path) as f:
            tree = ast.parse(f.read(), path)
        bps = {}
        for n in ast.walk(tree):
            if (isinstance(n, ast.Assign) and isinstance(n.value, ast.Call)
                    and getattr(n.value.func, "id", None) == "Blueprint"):
                bps[n.targets[0].id] = n.value.args[0].value
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for d in fn.decorator_list:
                if not (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                        and d.func.attr == "route"):
                    continue
                owner = d.func.value.id
                kw = {k.arg: k.value for k in d.keywords}
                name = kw["endpoint"].value if "endpoint" in kw else fn.name
                ep = name if owner == "app" else f"{bps[owner]}.{name}"
                methods = ({e.value.upper() for e in kw["methods"].elts}
                           if "methods" in kw else {"GET"})
                r = found.setdefault(ep, {"methods": set(), "paths": set(),
                                          "where": f"{os.path.basename(path)}:{fn.lineno}"})
                r["methods"] |= methods
                r["paths"].add(d.args[0].value)
    return found


def gated(routes):
    """The endpoints gate_decision() looks up in POLICY: /api/* and not
    exempt (it returns before the table for anything else)."""
    exempt = exempt_paths()
    return {ep: r for ep, r in routes.items()
            if any(p.startswith("/api/") and p not in exempt for p in r["paths"])}


class AccessPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.routes = find_routes()
        cls.gated = gated(cls.routes)

    def test_parser_sees_the_backend(self):
        # A broken parser that finds nothing would pass every check below.
        self.assertGreater(len(self.routes), 200)
        self.assertIn("case.list_cases", self.gated)
        self.assertIn("reinit_msi", self.gated)
        self.assertNotIn("auth.auth_login", self.gated)
        self.assertNotIn("health", self.gated)

    def test_every_gated_endpoint_has_a_rule(self):
        missing = sorted(f"{ep} ({r['where']})" for ep, r in self.gated.items()
                         if ep not in access_policy.POLICY)
        self.assertEqual(missing, [], "add these to services/access_policy.POLICY")

    def test_no_stale_keys(self):
        stale = sorted(set(access_policy.POLICY) - set(self.gated))
        self.assertEqual(stale, [], "POLICY names no gated route by these")

    def test_values_are_roles(self):
        for ep, value in access_policy.POLICY.items():
            for v in (value.values() if isinstance(value, dict) else [value]):
                role = v.role if isinstance(v, access_policy.Rule) else v
                self.assertIn(role, ROLES, ep)

    def test_method_dicts_cover_the_route(self):
        for ep, value in access_policy.POLICY.items():
            if isinstance(value, dict) and ep in self.gated:
                want = self.gated[ep]["methods"]
                self.assertEqual(set(value), want, f"{ep}: route serves {sorted(want)}")

    def test_get_only_superadmin_is_deliberate(self):
        lazy = sorted(ep for ep, r in self.gated.items()
                      if r["methods"] == {"GET"} and ep in access_policy.POLICY
                      and access_policy.rule_for(ep, "GET").role == SUPERADMIN
                      and ep not in GET_SUPERADMIN)
        self.assertEqual(lazy, [], "a read at SUPERADMIN: lower it, or add it to "
                                   "GET_SUPERADMIN with the reason")

    def test_allowlist_is_not_stale(self):
        for ep in GET_SUPERADMIN:
            self.assertIn(ep, self.gated, ep)
            self.assertEqual(access_policy.rule_for(ep, "GET").role, SUPERADMIN, ep)


if __name__ == "__main__":
    unittest.main()
