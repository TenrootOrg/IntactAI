"""Adopting a Velociraptor flow/hunt an investigator ran by hand.

WHY THIS EXISTS. Investigators work in the Velociraptor GUI in parallel with the
appliance. Until this feature a case could only ever contain runs Intact itself
dispatched (or an offline-collector ZIP), so the first piece of manual work an
analyst did detached the case from the incident permanently — the report,
timeline and graph kept describing the automated pass while the real
investigation walked away from it.

Adopting is deliberately NOT a second launch path. It starts no collection and
touches no endpoint: it reads rows the server already holds for an id the
operator types. Two properties make that safe, and both are easy to break
silently, which is what this file guards:

  * the id comes from an OPERATOR, and ids are interpolated straight into VQL
    downstream. Every other caller passes an id the appliance itself minted.
    Validation must therefore happen before anything else in the route.
  * only artifacts fusion has mappers for may enter the graph. The filter has to
    be on BOTH fetch branches — the hunt path and the flow path are separate
    loops, and a filter applied to one of them once before looked completely
    correct while changing nothing (measured: still 38 sources, 713,520 rows).

The third guard is duller and bites harder: a new run type has to be added to
SIX separate registries before it behaves like a run. Miss AGENTIC_TYPES and the
adopted data is never a case member and never fuses — the feature appears to
work, produces a green row, and silently contributes nothing.
"""

import ast
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROUTES = os.path.join(ROOT, "modules/backend/routes/velociraptor_routes.py")
DASH = os.path.join(ROOT, "modules/backend/routes/dashboard_routes.py")
STORE = os.path.join(ROOT, "modules/backend/services/fusion/store.py")
WS = os.path.join(ROOT, "modules/backend/services/workflow_service.py")
APP = os.path.join(ROOT, "modules/backend/app.py")
JS = os.path.join(ROOT, "modules/nginx/html/js/stores/workflows.js")
HTML = os.path.join(ROOT, "modules/nginx/html/partials/workflows.html")
PANEL = os.path.join(ROOT, "modules/nginx/html/partials/velociraptor.html")
VJS = os.path.join(ROOT, "modules/nginx/html/js/velociraptor.js")

TYPE = "velociraptor_adopt"


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def func_source(path, name):
    """The source text of one function, without importing its module."""
    tree = ast.parse(read(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(read(path), node)
    raise AssertionError(f"{name} not found in {path}")


def load_id_helpers():
    """Exec just the pure id helpers — importing the route module would drag the
    whole backend (grpc, pyvelociraptor) in for two functions."""
    src = read(ROUTES)
    tree = ast.parse(src)
    ns = {}

    # _adopt_normalize_id imports its validators at call time; supply real ones.
    import re
    _FLOW = re.compile(r'^F\.[0-9A-Z]{1,32}$')
    _HUNT = re.compile(r'^H\.[0-9A-Z]{1,32}$')

    def is_valid_flow_id(v):
        return bool(_FLOW.match(v or ""))

    def is_valid_hunt_id(v):
        return bool(_HUNT.match(v or ""))

    def _is_valid_hunt_or_derived_flow_id(v):
        if is_valid_hunt_id(v):
            return True
        if v.startswith('F.') and v.endswith('.H') and len(v) > 4:
            return is_valid_hunt_id('H.' + v[2:-2])
        return False

    fake_base = type("m", (), {
        "_is_valid_hunt_or_derived_flow_id": staticmethod(_is_valid_hunt_or_derived_flow_id)})
    fake_safety = type("m", (), {
        "is_valid_flow_id": staticmethod(is_valid_flow_id),
        "is_valid_client_id": staticmethod(lambda v: bool(re.match(r'^C\.[0-9a-f]{1,32}$', v or ""))),
    })

    real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "services.agentic.collectors._base":
            return fake_base
        if name == "services.vql_safety":
            return fake_safety
        return real_import(name, globals, locals, fromlist, level)

    ns["__builtins__"] = dict(
        (__builtins__ if isinstance(__builtins__, dict) else vars(__builtins__)))
    ns["__builtins__"]["__import__"] = fake_import

    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in (
                "_adopt_normalize_id", "_adopt_ids_in_details"):
            exec(compile(ast.Module([node], []), ROUTES, "exec"), ns)
    return ns



def run_worker(*, rows=None, artifacts=None, client_info=None, kind="flow",
               ident="F.ABC", fetch_raises=None, persist_raises=None):
    """EXECUTE _adopt_worker against fakes and report what it did.

    The rest of this file asserts on source text, which is the house style and
    catches a whole class of registry mistakes — but it cannot tell whether the
    worker actually reaches a terminal state, and that is the property that
    matters most. So this one runs it.
    """
    calls = {"status": [], "logs": [], "persisted": [], "details": {}}

    def update_run_status(rid, status, progress=None, error=None, **kw):
        calls["status"].append((status, progress, error))

    def add_log_to_run(rid, msg, level="info"):
        calls["logs"].append((level, msg))

    def get_existing_collection_results(rid, **kw):
        calls.setdefault("fetch_kwargs", []).append(kw)
        if fetch_raises:
            raise fetch_raises
        return (rows or {}), (artifacts or []), (client_info or {})

    def persist_pipeline_artifacts(rid, res):
        if persist_raises:
            raise persist_raises
        calls["persisted"].append(res)

    def mutate_run_details(rid, mutator):
        mutator(calls["details"])

    fake_collectors = type("m", (), {
        "get_existing_collection_results": staticmethod(get_existing_collection_results),
        "persist_pipeline_artifacts": staticmethod(persist_pipeline_artifacts)})
    fake_mapper = type("m", (), {"SUPPORTED_ARTIFACTS": frozenset({"a", "b", "c"})})
    fake_ws = type("m", (), {"mutate_run_details": staticmethod(mutate_run_details)})

    import builtins
    real_import = builtins.__import__

    def fake_import(name, g=None, l=None, fromlist=(), level=0):
        if name == "services.agentic.collectors":
            return fake_collectors
        if name == "services.fusion.mappers.agentic":
            return fake_mapper
        if name == "services.workflow_service":
            return fake_ws
        return real_import(name, g, l, fromlist, level)

    # The worker prints a traceback on its error path by design; stub it so a
    # deliberately-failing test does not look like a broken one in the output.
    quiet_tb = type("m", (), {"print_exc": staticmethod(lambda *a, **k: None),
                              "format_exc": staticmethod(lambda *a, **k: "")})
    ns = {"__builtins__": dict(vars(builtins)),
          "update_run_status": update_run_status,
          "add_log_to_run": add_log_to_run,
          "traceback": quiet_tb,
          "print": lambda *a, **k: None}
    ns["__builtins__"]["__import__"] = fake_import
    exec(compile(func_source(ROUTES, "_adopt_worker"), ROUTES, "exec"), ns)
    ns["_adopt_worker"]("run_1", kind, ident)
    calls["final"] = calls["status"][-1][0] if calls["status"] else None
    calls["error"] = calls["status"][-1][2] if calls["status"] else None
    return calls



def load_existing_run_finder():
    """Exec the real _adopt_existing_run with the DB lookup replaced, so the
    matching rules are tested rather than grepped."""
    src = read(ROUTES)
    tree = ast.parse(src)
    import builtins
    real_import = builtins.__import__
    holder = {}

    def fake_import(name, g=None, l=None, fromlist=(), level=0):
        if name == "services.workflow_service":
            return type("m", (), {
                "get_automation_runs_by_case": staticmethod(lambda cid: holder["runs"])})
        return real_import(name, g, l, fromlist, level)

    ns = {"__builtins__": dict(vars(builtins))}
    ns["__builtins__"]["__import__"] = fake_import
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in (
                "_adopt_existing_run", "_adopt_ids_in_details"):
            exec(compile(ast.Module([node], []), ROUTES, "exec"), ns)
        if isinstance(node, ast.Assign) and getattr(
                node.targets[0], "id", "") == "_ADOPT_DEAD_STATUSES":
            exec(compile(ast.Module([node], []), ROUTES, "exec"), ns)

    def find(runs, ident):
        holder["runs"] = runs
        return ns["_adopt_existing_run"]("case_x", ident)
    return find


class TestTheIdIsClassifiedBeforeItReachesVQL(unittest.TestCase):
    """A hunt-derived flow id (F.xxx.H) IS a hunt — get_existing_collection_results
    normalizes it to H.xxx before querying hunt_flows(). Classifying it as a flow
    sends it down the single-flow path, where it finds nothing and the operator
    is told their perfectly good id has no data."""

    def setUp(self):
        self.normalize = load_id_helpers()["_adopt_normalize_id"]

    def test_flow_id(self):
        self.assertEqual(self.normalize("F.CVJ8K2M4NQ1P0"), ("flow", "F.CVJ8K2M4NQ1P0"))

    def test_hunt_id(self):
        self.assertEqual(self.normalize("H.CVJ8K2M4NQ1P0"), ("hunt", "H.CVJ8K2M4NQ1P0"))

    def test_hunt_derived_flow_id_is_a_hunt(self):
        self.assertEqual(self.normalize("F.CVJ8K2M4NQ1P0.H"),
                         ("hunt", "F.CVJ8K2M4NQ1P0.H"))

    def test_surrounding_whitespace_is_forgiven(self):
        # Operators paste from the Velociraptor GUI; a trailing space is not an error.
        self.assertEqual(self.normalize("  F.CVJ8K2M4NQ1P0  "), ("flow", "F.CVJ8K2M4NQ1P0"))

    def test_rubbish_is_refused(self):
        for bad in ("", None, "hello", "F.", "C.1a2b3c4d", "F.abc'; DROP--",
                    "F.CVJ8K2M4NQ1P0; SELECT * FROM clients()"):
            with self.subTest(bad=bad):
                self.assertEqual(self.normalize(bad), (None, None))


class TestDuplicateDetectionSeesEveryLocatorShape(unittest.TestCase):
    """Runs record their Velociraptor locator four different ways, and a
    collection stores a LIST when several clients were selected. Reading only
    `flow_id` as a string means the duplicate check silently passes and the same
    evidence is adopted twice into one case."""

    def setUp(self):
        self.ids = load_id_helpers()["_adopt_ids_in_details"]

    def test_bare_string(self):
        self.assertIn("f.abc", self.ids({"flow_id": "F.ABC"}))

    def test_list_of_flows(self):
        got = self.ids({"flow_id": ["F.ABC", "F.DEF"]})
        self.assertEqual(got, {"f.abc", "f.def"})

    def test_hunt_and_offline_shapes(self):
        got = self.ids({"hunt_id": "H.ABC", "offline_flow_id": "F.DEF",
                        "offline_hunt_id": "H.GHI"})
        self.assertEqual(got, {"h.abc", "f.def", "h.ghi"})

    def test_empty_and_missing(self):
        self.assertEqual(self.ids({}), set())
        self.assertEqual(self.ids(None), set())
        self.assertEqual(self.ids({"flow_id": None, "hunt_id": ""}), set())


class TestTheSameHuntUnderBothItsNames(unittest.TestCase):
    """H.xxx and F.xxx.H are one hunt wearing two names. Comparing only the
    string typed lets an operator who pastes the other form adopt the same hunt
    twice, and every finding in it doubles."""

    def setUp(self):
        self.find = load_existing_run_finder()

    def test_hunt_id_matches_its_derived_flow_form(self):
        runs = [{"run_id": "r1", "status": "completed",
                 "details": {"hunt_id": "H.ABC"}}]
        self.assertIsNotNone(self.find(runs, "F.ABC.H"))

    def test_derived_flow_form_matches_the_hunt_id(self):
        runs = [{"run_id": "r1", "status": "completed",
                 "details": {"flow_id": "F.ABC.H"}}]
        self.assertIsNotNone(self.find(runs, "H.ABC"))

    def test_an_unrelated_id_does_not_match(self):
        runs = [{"run_id": "r1", "status": "completed",
                 "details": {"hunt_id": "H.ABC"}}]
        self.assertIsNone(self.find(runs, "H.DEF"))

    def test_it_matches_a_flow_inside_a_list(self):
        runs = [{"run_id": "r1", "status": "completed",
                 "details": {"flow_id": ["F.AAA", "F.BBB"]}}]
        self.assertEqual(self.find(runs, "F.BBB")["run_id"], "r1")

    def test_it_matches_an_ordinary_collection_not_just_an_adopt(self):
        # The case this meets most often: the flow is already in the case
        # because Intact launched it.
        runs = [{"run_id": "c1", "status": "completed",
                 "automation_type": "velociraptor_collection",
                 "details": {"flow_id": "F.AAA"}}]
        self.assertEqual(self.find(runs, "F.AAA")["run_id"], "c1")


class TestAFailedAttemptDoesNotBlockRetrying(unittest.TestCase):
    """A failed or cancelled adopt contributed nothing. Counting it as a
    duplicate turns one transient Velociraptor outage into a permanent refusal,
    with a 409 pointing at a run that has no data to fetch — found live."""

    def setUp(self):
        self.find = load_existing_run_finder()

    def test_a_failed_run_is_ignored(self):
        runs = [{"run_id": "r1", "status": "failed", "details": {"flow_id": "F.AAA"}}]
        self.assertIsNone(self.find(runs, "F.AAA"))

    def test_a_cancelled_run_is_ignored(self):
        runs = [{"run_id": "r1", "status": "cancelled", "details": {"flow_id": "F.AAA"}}]
        self.assertIsNone(self.find(runs, "F.AAA"))

    def test_a_completed_run_still_blocks(self):
        runs = [{"run_id": "r1", "status": "completed", "details": {"flow_id": "F.AAA"}}]
        self.assertEqual(self.find(runs, "F.AAA")["run_id"], "r1")

    def test_an_in_flight_run_still_blocks(self):
        # Two adopts of one id racing would fetch and persist the same rows twice.
        for st in ("running", "pending"):
            with self.subTest(status=st):
                runs = [{"run_id": "r1", "status": st, "details": {"flow_id": "F.AAA"}}]
                self.assertEqual(self.find(runs, "F.AAA")["run_id"], "r1")

    def test_a_later_successful_run_wins_over_an_earlier_failure(self):
        runs = [{"run_id": "bad", "status": "failed", "details": {"flow_id": "F.AAA"}},
                {"run_id": "good", "status": "completed", "details": {"flow_id": "F.AAA"}}]
        self.assertEqual(self.find(runs, "F.AAA")["run_id"], "good")

    def test_the_route_words_an_in_flight_collision_differently(self):
        # Telling someone to press Fetch results on a run that is still fetching
        # is the wrong instruction.
        src = func_source(ROUTES, "adopt_velociraptor_collection")
        self.assertIn("being adopted right now", src)
        self.assertIn('("pending", "running")', src)


class TestValidationHappensBeforeAnythingElse(unittest.TestCase):
    """These ids are interpolated raw into VQL downstream. Every other caller
    passes an id the appliance minted itself; this is the first that takes one
    from a person, so a malformed id must be refused before a run row exists, a
    channel is opened, or a docker exec is paid for."""

    def setUp(self):
        self.src = func_source(ROUTES, "adopt_velociraptor_collection")

    def test_id_is_normalized_before_the_run_is_created(self):
        self.assertLess(self.src.index("_adopt_normalize_id"),
                        self.src.index("create_automation_run"),
                        "the id must be validated before a run row is created")

    def test_no_client_id_is_asked_for(self):
        # The fetch enumerates every client and locates the flow itself, so a
        # client id bought nothing but a field the operator could get wrong.
        self.assertNotIn("client_id", self.src)

    def test_duplicate_check_precedes_the_run(self):
        self.assertLess(self.src.index("_adopt_existing_run"),
                        self.src.index("create_automation_run"))

    def test_duplicate_returns_409_and_names_the_run(self):
        self.assertIn("409", self.src)
        self.assertIn('"duplicate": True', self.src)


class TestOnlySupportedArtifactsAreRead(unittest.TestCase):
    """The hunt path and the flow path are SEPARATE fetch loops. A filter applied
    to one of them once looked entirely correct and changed nothing — measured on
    real hardware as still 38 sources / 713,520 rows. Both branches, every time."""

    def setUp(self):
        self.src = func_source(ROUTES, "_adopt_worker")

    def test_both_fetch_branches_filter(self):
        self.assertEqual(self.src.count("only_artifacts=SUPPORTED_ARTIFACTS"), 2,
                         "both the hunt and the flow fetch must pass the allowlist")

    def test_the_allowlist_is_fusions_own(self):
        self.assertIn("from services.fusion.mappers.agentic import SUPPORTED_ARTIFACTS",
                      self.src)

    def test_progress_is_logged(self):
        self.assertEqual(self.src.count("progress_log=True"), 2)


class TestTheWorkerAlwaysReachesATerminalState(unittest.TestCase):
    """A run left at 'running' is a row the operator can never clear. One marked
    'completed' with nothing in it is worse: the fuse counts it as a member that
    contributed zero and never looks at it again. These EXECUTE the worker."""

    def test_a_normal_fetch_completes_and_persists(self):
        c = run_worker(rows={"a": [{"x": 1}, {"x": 2}]}, artifacts=["a"],
                       client_info={"C.1": {"hostname": "HOST1"}})
        self.assertEqual(c["final"], "completed")
        self.assertEqual(c["persisted"], [{"a": [{"x": 1}, {"x": 2}]}])
        self.assertEqual(c["details"]["total_rows"], 2)

    def test_an_unlocatable_id_says_so_rather_than_blaming_the_allowlist(self):
        # client_info empty == the id is not on this server. Reporting "no
        # supported artifacts" here sends someone to argue about the allowlist
        # over a transposed character.
        c = run_worker(rows={}, artifacts=[], client_info={})
        self.assertEqual(c["final"], "failed")
        self.assertIn("not found on the Velociraptor server", c["error"])
        self.assertNotIn("none of its artifacts", c["error"])

    def test_a_located_collection_with_nothing_mapped_names_the_host(self):
        c = run_worker(rows={}, artifacts=[], client_info={"C.1": {"hostname": "HOST1"}})
        self.assertEqual(c["final"], "failed")
        self.assertIn("none of its artifacts", c["error"])
        self.assertIn("HOST1", c["error"])
        self.assertNotIn("not found on the Velociraptor server", c["error"])

    def test_a_fetch_that_raises_marks_the_run_failed(self):
        c = run_worker(fetch_raises=RuntimeError("velociraptor is down"))
        self.assertEqual(c["final"], "failed")
        self.assertIn("velociraptor is down", c["error"])

    def test_a_persist_that_raises_marks_the_run_failed(self):
        # The rows were read but never written. Completing here would leave a
        # member run the fuse counts and can never read.
        c = run_worker(rows={"a": [{"x": 1}]}, artifacts=["a"],
                       client_info={"C.1": {"hostname": "H"}},
                       persist_raises=OSError("disk full"))
        self.assertEqual(c["final"], "failed")
        self.assertIn("disk full", c["error"])

    def test_it_never_ends_on_running(self):
        for kw in ({}, {"rows": {"a": [{"x": 1}]}, "artifacts": ["a"],
                        "client_info": {"C.1": {"hostname": "H"}}},
                   {"fetch_raises": RuntimeError("boom")}):
            with self.subTest(kw=sorted(kw)):
                self.assertIn(run_worker(**kw)["final"], ("completed", "failed"))

    def test_a_flow_persists_the_client_it_resolved_on(self):
        # At fuse time _velo_hunt_contribution re-pulls live and needs flow_id
        # AND client_id together. Nobody supplies one, so the client the fetch
        # resolved the flow on MUST be written back — without it the adopted
        # flow fuses once and can never be re-read.
        c = run_worker(kind="flow", rows={"a": [{"x": 1}]}, artifacts=["a"],
                       client_info={"C.abc": {"hostname": "HOST1"}})
        self.assertEqual(c["details"]["client_id"], "C.abc")

    def test_a_hunt_does_not_invent_a_client_id(self):
        # A hunt spans many clients; pinning one would make the re-pull read a
        # single host's slice as if it were the whole hunt.
        c = run_worker(kind="hunt", ident="H.ABC", rows={"a": [{"x": 1}]},
                       artifacts=["a"],
                       client_info={"C.1": {"hostname": "H1"}, "C.2": {"hostname": "H2"}})
        self.assertNotIn("client_id", c["details"])

    def test_hostnames_reach_the_run_for_every_client(self):
        c = run_worker(kind="hunt", ident="H.ABC", rows={"a": [{"x": 1}]},
                       artifacts=["a"],
                       client_info={"C.1": {"hostname": "H1"}, "C.2": {"hostname": "H2"}})
        self.assertEqual(c["details"]["hostnames"], {"C.1": "H1", "C.2": "H2"})

    def test_the_allowlist_is_passed_on_whichever_branch_runs(self):
        for kind, ident in (("flow", "F.ABC"), ("hunt", "H.ABC")):
            with self.subTest(kind=kind):
                c = run_worker(kind=kind, ident=ident, rows={"a": [{"x": 1}]},
                               artifacts=["a"], client_info={"C.1": {"hostname": "H"}})
                kw = c["fetch_kwargs"][0]
                self.assertIn("only_artifacts", kw)
                self.assertTrue(kw["only_artifacts"])
                self.assertTrue(kw.get("progress_log"))

    def test_no_client_scoping_is_sent(self):
        c = run_worker(kind="flow", rows={"a": [{"x": 1}]}, artifacts=["a"],
                       client_info={"C.1": {"hostname": "H"}})
        self.assertNotIn("client_ids", c["fetch_kwargs"][0])


class TestEveryRegistryKnowsTheType(unittest.TestCase):
    """Six registries. Missing AGENTIC_TYPES is the quiet one: the run is never a
    case member, never arms the fuse, and still shows green."""

    def test_agentic_types_makes_it_a_case_member(self):
        self.assertIn(f'"{TYPE}"', read(WS).split("AGENTIC_TYPES")[1].split("}")[0])

    def test_velociraptor_types_passes_the_fusion_gate(self):
        self.assertIn(f'"{TYPE}"', read(STORE).split("_VELOCIRAPTOR_TYPES")[1].split("}")[0])

    def test_contribution_dispatches_it_like_a_hunt(self):
        # _velo_hunt_contribution already handles BOTH a hunt_id and a
        # flow_id+client_id locator, so adopt needs no branch of its own.
        src = read(STORE)
        marker = 'if atype in ("velociraptor_hunt", "velociraptor_offline_import",'
        self.assertIn(marker, src)
        self.assertIn(f'"{TYPE}")', src[src.index(marker):src.index(marker) + 200])

    def test_recollectable_so_fetch_results_works(self):
        self.assertIn(f'"{TYPE}"', read(DASH).split("_RECOLLECTABLE")[1].split(")")[0])

    def test_reaped_on_restart(self):
        self.assertIn(f'"{TYPE}"', read(APP).split("_REAP_TYPES")[1].split("}")[0])

    def test_workflows_ui_knows_it(self):
        self.assertIn(f"{TYPE}:", read(JS), "needs a colour or the chip reads black-on-dark")
        html = read(HTML)
        self.assertIn(f'value="{TYPE}"', html, "needs a type-filter option")
        self.assertIn(f"'{TYPE}'].includes(run.type)", html,
                      "an adopted hunt keeps collecting — Fetch results must be offered")


class TestTheOperatorCanFindIt(unittest.TestCase):
    """The panel lives beside Collections, not under Offline Collectors: the data
    is on the live server, not in an air-gapped ZIP."""

    def test_the_tab_exists(self):
        panel = read(PANEL)
        self.assertIn("forensicsTab = 'adopt'", panel)
        self.assertIn("forensicsTab === 'adopt'", panel)
        self.assertIn('id="adopt-id"', panel)
        self.assertNotIn('id="adopt-client-id"', panel)

    def test_it_says_no_collection_is_started(self):
        # The single most important thing to convey: this does not touch the
        # endpoint. An operator who thinks it might will not use it during an
        # incident.
        panel = read(PANEL).lower()
        self.assertTrue("nothing is collected from the endpoint" in panel
                        or "no collection is started" in panel)

    def test_it_hands_off_to_the_workflows_tab(self):
        # Progress, the full log and Stop belong on the run row like every other
        # module — not in a second progress UI on this page.
        vjs = read(VJS)
        self.assertIn("adoptVelociraptorId", vjs)
        adopt = vjs[vjs.index("async function adoptVelociraptorId"):]
        self.assertIn("switchTab('workflows')", adopt)

    def test_a_duplicate_is_shown_as_a_warning_not_an_error(self):
        vjs = read(VJS)
        adopt = vjs[vjs.index("async function adoptVelociraptorId"):]
        self.assertIn("409", adopt)


if __name__ == "__main__":
    unittest.main(verbosity=2)
