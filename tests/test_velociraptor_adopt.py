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
    """H.xxx and F.xxx.H are one hunt wearing two names. If the duplicate check
    compares only the string typed, an operator who pastes the other form adopts
    the same hunt a second time and every finding in it doubles."""

    def test_both_directions_are_compared(self):
        src = func_source(ROUTES, "_adopt_existing_run")
        self.assertIn('"H." + ident[2:-2]', src)
        self.assertIn('"F." + ident[2:] + ".H"', src)


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
    contributed zero and never looks at it again."""

    def setUp(self):
        self.src = func_source(ROUTES, "_adopt_worker")

    def test_empty_result_fails_rather_than_completing(self):
        head, _, tail = self.src.partition("if total == 0:")
        self.assertTrue(tail, "the zero-row branch must exist")
        branch = tail[:tail.index("hostnames =")]
        self.assertIn('update_run_status(run_id, "failed"', branch)
        self.assertNotIn('"completed"', branch)

    def test_exceptions_mark_the_run_failed(self):
        self.assertIn('update_run_status(run_id, "failed", error=str(e))', self.src)

    def test_a_flow_persists_the_client_it_resolved_on(self):
        # At fuse time _velo_hunt_contribution re-pulls live and needs flow_id
        # AND client_id together. Nobody supplies one, so the client the fetch
        # resolved the flow on MUST be written back — without it the adopted
        # flow fuses once and can never be re-read.
        self.assertIn('resolved = next(iter(client_info or {}), None)', self.src)
        self.assertIn('det["client_id"] = resolved', self.src)


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
