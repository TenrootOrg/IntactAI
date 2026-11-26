"""Restricted cases (services/case_access.py) and the routes that follow them.

Real SQLite in a temp dir, the real store and workflow service, the real route
functions with a stand-in `flask` when Flask is not installed (as in
test_workflows_list_summary.py). Covered: who sees a restricted case, the
request-level refusal (URL, run, active-case header/cookie), the lists that drop
it, Operators seeing a case's export runs but not host-level ones, the
Read-only picture-only rule for case files, and the Velociraptor/Timesketch
grants for a restricted case's org and sketch (with fakes for both tools).
"""
import json
import os
import re
import shutil
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
_BASE = tempfile.mkdtemp(prefix="intact-case-access-")
os.environ["INTACT_STORAGE_BASE"] = _BASE
import atexit  # noqa: E402
atexit.register(shutil.rmtree, _BASE, True)

try:
    import flask  # noqa: F401
except ImportError:
    _flask = types.ModuleType("flask")

    class _Blueprint:
        def __init__(self, *a, **k):
            pass

        def __getattr__(self, _name):
            # route(...), errorhandler(X), before_request, after_request...: the
            # function itself, undecorated.
            return lambda *a, **k: a[0] if a and isinstance(a[0], types.FunctionType) else (lambda f: f)
    _flask.Blueprint = _Blueprint
    _flask.jsonify = lambda *a, **k: a[0] if a else k
    _flask.g = types.SimpleNamespace(case_id=None)
    _flask.request = types.SimpleNamespace(args={}, headers={}, cookies={}, view_args={}, endpoint=None)
    _flask.has_request_context = lambda: False
    _flask.session = {}
    _flask.Response = object
    _flask.send_file = lambda *a, **k: types.SimpleNamespace(headers={}, args=a, kw=k)
    sys.modules["flask"] = _flask

import _optional_deps  # noqa: F401,E402
from services.storage import init_storage, list_workflow_summaries  # noqa: E402

init_storage()
import flask as F  # noqa: E402  (the stand-in, or the real one)
from services import case_access, users  # noqa: E402
from services import workflow_service as ws  # noqa: E402
from services.fusion import store  # noqa: E402
import importlib.util  # noqa: E402


def _load_route(name):
    # The file alone: routes/__init__ would import every blueprint in the backend.
    spec = importlib.util.spec_from_file_location(
        f"{name}_under_test", os.path.join(ROOT, f"modules/backend/routes/{name}.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


dashboard_routes = _load_route("dashboard_routes")
case_routes = _load_route("case_routes")


def sess(uid):
    return {"uid": uid, "user": (users.get(uid) or {}).get("username")}


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        users.ensure_table()
        c = users.get_connection()
        c.execute("DELETE FROM users")
        c.execute("DELETE FROM workflows")
        c.commit()
        users.invalidate()
        case_access.invalidate()
        cls.boss = users.create("boss", "h", users.SUPERADMIN, "t", False)
        cls.adam = users.create("adam", "h", users.ADMIN, "t", False)
        cls.olga = users.create("olga", "h", users.OPERATOR, "t", False)
        cls.otto = users.create("otto", "h", users.OPERATOR, "t", False)
        cls.rita = users.create("rita", "h", users.READONLY, "t", False)
        store.ensure_system_case()
        cls.open = store.create_case("Open case")
        cls.secret = store.create_case("Secret case", created_by="olga")
        store.update_case_info(cls.secret, {"velo_org": "OSEC1"})
        with mock.patch("services.tool_accounts.request_reconcile") as rec:
            res = case_access.set_access(cls.secret, True, ["rita"], users.get(cls.olga))
        assert res.get("restricted") and rec.called, res
        cls.secret_run = ws.create_automation_run("velociraptor_collection", "c", details={},
                                                  case_id=cls.secret)
        cls.open_run = ws.create_automation_run("velociraptor_collection", "c", details={},
                                                case_id=cls.open)
        cls.secret_export = ws.create_automation_run(
            "case_export", "Export case: Secret case", details={"case_id": cls.secret})
        cls.open_export = ws.create_automation_run(
            "case_export", "Export case: Open case",
            details={"case_id": cls.open, "started_in": cls.open})
        cls.upgrade = ws.create_automation_run("upgrade", "Upgrade", details={})


class Visibility(Fixture):
    def test_the_list_the_creator_and_the_super_admin(self):
        r = case_access.restricted_cases()[self.secret]
        self.assertEqual(r["users"], {"olga", "rita"}, "the creator is kept on the list")
        see = {n: case_access.can_see(self.secret, users.get(u)) for n, u in
               (("boss", self.boss), ("adam", self.adam), ("olga", self.olga),
                ("otto", self.otto), ("rita", self.rita))}
        self.assertEqual(see, {"boss": True, "adam": False, "olga": True, "otto": False, "rita": True})
        self.assertTrue(case_access.can_see(self.secret, None), "the box itself")
        for u in (self.adam, self.otto):
            self.assertTrue(case_access.can_see(self.open, users.get(u)))

    def test_visible_and_hidden_sets(self):
        self.assertIsNone(case_access.visible_case_ids(users.get(self.boss)))
        self.assertIsNone(case_access.visible_case_ids(users.get(self.olga)))
        vis = case_access.visible_case_ids(users.get(self.otto))
        self.assertIn(self.open, vis)
        self.assertNotIn(self.secret, vis)
        self.assertEqual(case_access.hidden_case_ids(users.get(self.adam)), {self.secret})

    def test_request_refusal_case_run_and_the_run_about_the_case(self):
        refuse = case_access.request_refusal
        self.assertEqual(refuse(self.secret, sess(self.otto)), "case not found")
        self.assertIsNone(refuse(self.secret, sess(self.rita)))
        self.assertIsNone(refuse(self.secret, {}), "no session: the box")
        self.assertTrue(refuse(None, sess(self.otto), run_id=self.secret_run))
        self.assertTrue(refuse(None, sess(self.adam), run_id=self.secret_export),
                        "an export lives in System but is about the case")
        self.assertIsNone(refuse(None, sess(self.otto), run_id=self.open_export))
        self.assertIsNone(refuse(None, sess(self.boss), run_id=self.secret_export))
        gone = {"uid": 999999}
        self.assertEqual(refuse(self.secret, gone), "case not found", "a deleted user is nobody, not the box")

    def test_check_request_reads_the_url_and_the_active_case(self):
        def req(endpoint="case.get_case", view_args=None, header=None, cookie=None):
            return types.SimpleNamespace(endpoint=endpoint, view_args=view_args or {},
                                         headers={"X-Case-Id": header} if header else {},
                                         cookies={"intact_case": cookie} if cookie else {})
        chk = case_access.check_request
        self.assertTrue(chk(req(view_args={"case_id": self.secret}), sess(self.otto)))
        self.assertTrue(chk(req(view_args={"run_id": self.secret_run}), sess(self.otto)))
        self.assertTrue(chk(req("dashboard.get_all_automations", header=self.secret), sess(self.otto)))
        self.assertTrue(chk(req("dashboard.get_all_automations", cookie=self.secret), sess(self.otto)))
        # The case list ignores a stale active case: it is how the page recovers.
        self.assertIsNone(chk(req("case.list_cases", header=self.secret, cookie=self.secret), sess(self.otto)))
        self.assertIsNone(chk(req("auth.auth_status", cookie=self.secret), sess(self.otto)))
        self.assertTrue(chk(req("case.list_cases", view_args={"case_id": self.secret}), sess(self.otto)))
        self.assertIsNone(chk(req(view_args={"case_id": self.secret}, header=self.secret), sess(self.olga)))
        self.assertIsNone(chk(req(view_args={"case_id": self.open}, header=self.open), sess(self.otto)))

    def test_who_may_change_it(self):
        may = case_access.may_change
        self.assertTrue(may(self.secret, users.get(self.boss)))
        self.assertTrue(may(self.secret, users.get(self.olga)), "an Operator on the list")
        self.assertFalse(may(self.secret, users.get(self.adam)), "an Admin not on the list")
        self.assertFalse(may(self.secret, users.get(self.rita)), "Read-only never")
        self.assertTrue(may(self.open, users.get(self.otto)), "any Operator may restrict an open case")

    def test_set_access_validates_and_keeps_the_actor(self):
        self.assertIn("no such user", case_access.set_access(self.open, True, ["nobody"], None)["error"])
        default = store.ensure_default_case()
        self.assertIn("built-in", case_access.set_access(default, True, [], None)["error"])
        self.assertIn("list", case_access.set_access(self.open, True, "otto", None)["error"])
        with mock.patch("services.tool_accounts.request_reconcile") as rec:
            res = case_access.set_access(self.open, True, [], users.get(self.otto))
            self.assertEqual(res["allowed_users"], ["otto"], "restricting must not lock the actor out")
            self.assertFalse(case_access.can_see(self.open, users.get(self.adam)), "seen at once")
            res = case_access.set_access(self.open, False, ["otto"], users.get(self.otto))
            self.assertTrue(case_access.can_see(self.open, users.get(self.adam)))
            self.assertEqual(rec.call_count, 2)
            case_access.set_access(self.open, False, ["otto"], users.get(self.otto))
            self.assertEqual(rec.call_count, 2, "no change, no reconcile")


class OrgOfItsOwn(Fixture):
    """A restricted case's Velociraptor org is its own: no other case may sit in
    it, or everyone who sees that case reads this one's Velociraptor data."""

    def test_restricting_a_case_in_a_shared_org_is_refused(self):
        a = store.create_case("Shared A")
        b = store.create_case("Shared B")
        for cid in (a, b):
            store.update_case_info(cid, {"velo_org": "OSHAR"})
        res = case_access.set_access(a, True, [], users.get(self.otto))
        self.assertIn("shared with Shared B", res.get("error", ""))
        self.assertNotIn(a, case_access.restricted_cases())

    def test_baseline_rows_follow_their_source_case(self):
        base = {"run_id": "b1", "automation_type": "baseline", "case_id": None,
                "details": {"source_case": self.secret}}
        self.assertFalse(case_access.run_visible(base, users.get(self.otto)))
        self.assertTrue(case_access.run_visible(base, users.get(self.rita)))

    def test_a_db_lock_keeps_the_last_list(self):
        import sqlite3
        case_access.restricted_cases()                          # a snapshot exists
        case_access._snapshot_at = 0                             # noqa: SLF001 -- due for refresh
        locked = mock.Mock()
        locked.execute.side_effect = sqlite3.OperationalError("database is locked")
        with mock.patch("services.storage.base.get_connection", lambda: locked):
            self.assertIn(self.secret, case_access.restricted_cases())


class Listings(Fixture):
    def ids(self, **kw):
        return {r["run_id"] for r in list_workflow_summaries(**kw)[0]}

    def test_summaries_drop_the_runs_of_a_hidden_case(self):
        hidden = case_access.hidden_case_ids(users.get(self.otto))
        got = self.ids(hidden_case_ids=hidden, linked_types=case_access.CASE_RUN_TYPES)
        self.assertNotIn(self.secret_run, got)
        self.assertNotIn(self.secret_export, got, "nor the export about it")
        self.assertNotIn(self.secret, got, "nor the case row itself")
        self.assertIn(self.open_run, got)
        self.assertIn(self.open_export, got)
        _, total = list_workflow_summaries(hidden_case_ids=hidden, linked_types=case_access.CASE_RUN_TYPES)
        self.assertEqual(total, len(got), "filtered in SQL: total is exact")

    def test_a_case_lists_its_own_export(self):
        got = self.ids(case_id=self.open, linked_types=case_access.CASE_RUN_TYPES)
        self.assertEqual(got, {self.open_run, self.open_export})
        self.assertEqual(self.ids(case_id=self.open), {self.open_run}, "unchanged without linked_types")

    def test_an_import_is_listed_where_it_started_not_in_every_case(self):
        # The bundle may be a restricted case: its file name and log are not for
        # the Workflows page of every case.
        imp = ws.create_automation_run("case_import", "Import case: secret.intactcase.zip",
                                       details={"filename": "secret.intactcase.zip", "started_in": self.open})
        try:
            linked = case_access.CASE_RUN_TYPES
            self.assertIn(imp, self.ids(case_id=self.open, linked_types=linked))
            self.assertNotIn(imp, self.ids(case_id=self.secret, linked_types=linked))
            ws.update_run_status(imp, "completed", details={"case_id": self.secret})
            self.assertIn(imp, self.ids(case_id=self.secret, linked_types=linked), "then in the case it made")
        finally:
            from services.file_storage_service import delete_workflow
            delete_workflow(imp)

    def _automations(self, uid, case_id=None):
        with mock.patch.object(F, "g", types.SimpleNamespace(case_id=case_id)), \
                mock.patch.object(F, "request", types.SimpleNamespace(args={})), \
                mock.patch.object(F, "session", sess(uid)):
            return {r["id"] for r in dashboard_routes.get_all_automations()["runs"]}

    def test_operators_see_export_runs_not_upgrade_runs(self):
        op = self._automations(self.otto)
        self.assertIn(self.open_export, op)
        self.assertNotIn(self.upgrade, op)
        self.assertNotIn(self.secret_export, op)
        self.assertIn(self.open_export, self._automations(self.otto, case_id=self.open),
                      "on the case's own Workflows page")
        ro = self._automations(self.rita)
        self.assertNotIn(self.open_export, ro, "Read-only: no System-type runs")
        self.assertIn(self.secret_run, ro, "Read-only on the list sees the case's runs")
        admin = self._automations(self.adam)
        self.assertIn(self.upgrade, admin)
        self.assertNotIn(self.secret_export, admin)

    def test_one_run_by_id(self):
        def visible(uid, rid):
            with mock.patch.object(F, "g", types.SimpleNamespace(case_id=None)), \
                    mock.patch.object(F, "session", sess(uid)):
                return dashboard_routes._run_visible_in_active_workspace(ws.get_automation_run(rid))
        self.assertTrue(visible(self.otto, self.open_export))
        self.assertFalse(visible(self.otto, self.upgrade))
        self.assertFalse(visible(self.otto, self.secret_export))
        self.assertTrue(visible(self.olga, self.secret_export))
        self.assertFalse(visible(self.rita, self.open_export))
        self.assertTrue(visible(self.adam, self.upgrade))

    def test_the_case_list(self):
        def names(uid):
            with mock.patch.object(case_routes, "session", sess(uid)), \
                    mock.patch.object(case_routes, "jsonify", lambda x: x):
                return {c["name"]: c["restricted"] for c in case_routes.list_cases()["cases"]}
        self.assertNotIn("Secret case", names(self.otto))
        self.assertNotIn("Secret case", names(self.adam))
        self.assertEqual(names(self.rita).get("Secret case"), True, "listed, with the lock")
        self.assertEqual(names(self.boss).get("Open case"), False)


class CaseFiles(Fixture):
    """Read-only: the report's pictures in the page, never the raw evidence."""

    def get(self, uid, inline, name="shot.png", kind="image"):
        item = {"id": "f1", "file_name": name, "kind": kind}
        sent = []
        req = types.SimpleNamespace(args={"inline": "1"} if inline else {})
        with mock.patch.object(case_routes, "session", sess(uid)), \
                mock.patch.object(case_routes, "request", req), \
                mock.patch.object(case_routes, "jsonify", lambda x: x), \
                mock.patch.object(case_routes._case_files, "listing", lambda d: [item]), \
                mock.patch.object(case_routes._case_files, "path_of", lambda c, f: "/x/" + f), \
                mock.patch.object(case_routes, "send_file",
                                  lambda *a, **k: sent.append(k) or types.SimpleNamespace(headers={})):
            out = case_routes.download_case_file(self.open, "f1")
        return (out[1] if isinstance(out, tuple) else 200), sent

    def test_read_only_gets_inline_pictures_only(self):
        code, sent = self.get(self.rita, inline=True)
        self.assertEqual((code, sent[0].get("as_attachment")), (200, False))
        self.assertEqual(self.get(self.rita, inline=False)[0], 403, "the raw file")
        self.assertEqual(self.get(self.rita, inline=True, name="page.html", kind="document")[0], 403)
        self.assertEqual(self.get(self.rita, inline=True, name="x.svg")[0], 403, "not a raster picture")

    def test_operators_still_download_raw_files(self):
        code, sent = self.get(self.otto, inline=False, name="dump.bin", kind="document")
        self.assertEqual((code, sent[0].get("as_attachment")), (200, True))


class FakeVelo:
    """{user: {org: roles}}: user_create/user_grant(roles=) replace the roles in
    the orgs listed, user_grant(policy=dict()) drops them (0.77.4)."""

    def __init__(self):
        self.users = {}

    @staticmethod
    def _arg(vql, name):
        import ast
        m = re.search(rf"\b{name}=('[^']*'|\[[^\]]*\])", vql)
        return ast.literal_eval(m.group(1)) if m else None

    def query(self, vql, timeout=120):
        user = self._arg(vql, "user")
        if "user_create(" in vql or ("user_grant(" in vql and "roles=" in vql):
            for o in self._arg(vql, "orgs"):
                self.users.setdefault(user, {})[o] = self._arg(vql, "roles")
        elif "user_grant(" in vql:
            for o in self._arg(vql, "orgs"):
                self.users.get(user, {}).pop(o, None)
        elif "user(" in vql:
            return [{"u": {"name": user} if user in self.users else None}]
        return [{}]


class ToolGrants(Fixture):
    PW = "A" * 20 + "b_-9" * 5

    def test_velociraptor_grants_the_restricted_org_only_to_the_list(self):
        from services.tool_accounts import velociraptor as velo
        fake = FakeVelo()
        with mock.patch.object(velo, "_query", fake.query), \
                mock.patch.object(velo, "org_list", lambda: [(o, o) for o in ("root", "OSEC1", "OPEN2")]):
            for name, role in (("olga", "operator"), ("otto", "operator"), ("adam", "admin"),
                               ("boss-intact", "superadmin")):
                velo.ensure(name, self.PW, velo.tool_role(role), set_password=True)
            # otto held the org before the case was restricted: the next pass takes it.
            fake.users["otto"]["OSEC1"] = ["investigator"]
            velo.ensure("otto", self.PW, velo.tool_role("operator"), set_password=False)
            velo.ensure("otto", self.PW, velo.tool_role("operator"), set_password=False)
        self.assertEqual(set(fake.users["olga"]), {"root", "OSEC1", "OPEN2"})
        self.assertEqual(set(fake.users["otto"]), {"root", "OPEN2"})
        self.assertEqual(set(fake.users["adam"]), {"root", "OPEN2"}, "an Admin not on the list")
        self.assertEqual(set(fake.users["boss-intact"]), {"root", "OSEC1", "OPEN2"}, "the Super-admin")

    def test_timesketch_is_told_which_sketches_are_restricted(self):
        from services.tool_accounts import timesketch as ts
        self.assertEqual(ts._restricted_for("olga"), {"Secret case": True})
        self.assertEqual(ts._restricted_for("otto"), {"Secret case": False})
        self.assertEqual(ts._restricted_for("boss-intact"), {"Secret case": True})

    def test_timesketch_script_moves_the_sketch_from_the_team_to_the_list(self):
        from services.tool_accounts import timesketch as ts
        state = run_ts_script(ts._SCRIPT, ["olga", "otto"], {"Secret case": None, "Open case": None})
        # Before any restriction: the team has both sketches.
        self.assertEqual(state.acl("Secret case"), {("group", "intact-team", "read"), ("group", "intact-team", "write")})
        run_ts_script(ts._SCRIPT, ["olga"], {"Secret case": True}, state)
        run_ts_script(ts._SCRIPT, ["otto"], {"Secret case": False}, state)
        self.assertEqual(state.acl("Secret case"), {("user", "olga", "read"), ("user", "olga", "write")})
        self.assertIn(("group", "intact-team", "read"), state.acl("Open case"))
        run_ts_script(ts._SCRIPT, ["olga"], {"Secret case": False}, state)       # taken off the list
        self.assertEqual(state.acl("Secret case"), set())
        run_ts_script(ts._SCRIPT, ["olga"], {}, state)                            # opened again
        self.assertIn(("group", "intact-team", "write"), state.acl("Secret case"))


class AccessForm(unittest.TestCase):
    """cases.html: the Restricted toggle and picker (caseAccessHtml is pure)."""

    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_the_form_says_what_cannot_be_restricted(self):
        import subprocess
        html = open(os.path.join(ROOT, "modules/nginx/html/cases.html"), encoding="utf-8").read()
        fn = re.search(r"function caseAccessHtml\(a\)\{.*?\n\}", html, re.S).group(0)
        helpers = "".join(re.search(rf"function {n}\(s\)\{{.*?;\}}\n", html, re.S).group(0) for n in ("esc", "jsa"))
        a = {"case_id": "case_1", "restricted": True, "allowed_users": ["rita"], "created_by": "olga",
             "velo_org": "root", "may_change": True,
             "users": [{"username": u, "role": r, "role_label": r} for u, r in
                       (("boss", "superadmin"), ("olga", "operator"), ("otto", "operator"), ("rita", "readonly"))]}
        js = helpers + fn + f"\nconsole.log(caseAccessHtml({json.dumps(a)}));" \
            + f"console.log('@@'+caseAccessHtml({json.dumps(dict(a, may_change=False))}));"
        out = subprocess.run(["node", "-e", js], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        rw, ro = out.stdout.split("@@")
        self.assertIn("Also visible to everyone in Kibana and VolWeb", rw)
        self.assertIn("root Velociraptor org", rw)
        checked = re.findall(r'value="(\w+)" (checked)? ?(disabled)?', rw)
        self.assertEqual({u: (bool(c), bool(d)) for u, c, d in checked},
                         {"boss": (True, True), "olga": (True, True), "otto": (False, False), "rita": (True, False)})
        self.assertIn("saveCaseAccess('case_1')", rw)
        self.assertNotIn("saveCaseAccess", ro)
        self.assertIn('id="cdf-restricted" checked disabled', ro)

    def test_export_and_import_are_operator_buttons_on_the_workflows_page(self):
        html = open(os.path.join(ROOT, "modules/nginx/html/cases.html"), encoding="utf-8").read()
        for btn in (r"<button[^>]*exportWorkspace", r"<button[^>]*case-import-file"):
            tag = re.search(btn, html).group(0)
            self.assertIn('data-needs="write"', tag)
        self.assertNotIn("gotoSystemWorkflows", html)


class _TsState:
    def __init__(self, sketch_names):
        self.users, self.groups = {}, {}
        self.sketches = [types.SimpleNamespace(name=n, acl=[], user=None) for n in sketch_names]

    def acl(self, name):
        sk = next(s for s in self.sketches if s.name == name)
        return {("user", a.user.username, a.permission) if a.user else ("group", a.group.name, a.permission)
                for a in sk.acl}


def run_ts_script(script, names, restricted, state=None):
    """Run the provider's in-container script against fake Timesketch models."""
    state = state or _TsState([n for n in restricted])
    import contextlib

    class Q:
        def __init__(self, store):
            self.store = store

        def filter_by(self, **kw):
            key = kw.get("username") or kw.get("name")
            return types.SimpleNamespace(first=lambda: self.store.get(key))

    class User:
        query = Q(state.users)

        def __init__(self, username, name):
            self.username, self.name, self.groups, self.admin, self.active = username, name, [], False, True

    class Group:
        query = Q(state.groups)

        def __init__(self, name, display_name):
            self.name = name

    class ACE:
        def __init__(self, permission, user=None, group=None):
            self.permission, self.user, self.group = permission, user, group

    def get_ace(self, perm, user=None, group=None, check_group=True):
        if group:
            return [a for a in self.acl if a.group is group and a.permission == perm]
        return [a for a in self.acl if a.user is user and a.group is None and a.permission == perm]

    for sk in state.sketches:
        sk.AccessControlEntry = ACE
        sk._get_ace = types.MethodType(get_ace, sk)

    class Sketch:
        query = types.SimpleNamespace(all=lambda: state.sketches)

    def add(obj):
        if isinstance(obj, User):
            state.users[obj.username] = obj
        elif isinstance(obj, Group):
            state.groups[obj.name] = obj

    mods = {
        "timesketch": types.ModuleType("timesketch"),
        "timesketch.app": types.SimpleNamespace(create_app=lambda: types.SimpleNamespace(
            app_context=contextlib.nullcontext)),
        "timesketch.models": types.SimpleNamespace(db_session=types.SimpleNamespace(add=add, commit=lambda: None)),
        "timesketch.models.sketch": types.SimpleNamespace(Sketch=Sketch),
        "timesketch.models.user": types.SimpleNamespace(Group=Group, User=User),
    }
    for name in names:
        with mock.patch.dict(sys.modules, mods), \
                mock.patch.object(sys, "argv", ["-", "ensure", name, "user", "intact-team",
                                                json.dumps({k: v for k, v in restricted.items() if v is not None})]), \
                mock.patch("builtins.print"):
            exec(compile(script, "ts-script", "exec"), {"__name__": "__main__"})
    return state


if __name__ == "__main__":
    unittest.main()
