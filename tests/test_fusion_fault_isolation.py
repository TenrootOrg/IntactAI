"""One bad item must never lose the whole case graph.

THE INCIDENT. A live case fused two agentic runs cleanly. Then a Velociraptor
collection landed and the automatic re-fuse died:

    Refusion · mapped 3/3 run(s) ... 40%
    Refusion failed ... TypeError: unhashable type: 'list'

and the case was left with NO graph -- not a graph missing the bad data, no
graph at all. Two separate defects made that possible:

  1. ROOT CAUSE. FusionGraph.upsert() keeps conflicting attribute values with
     provenance, and deduplicated them by building a SET. Attribute values are
     arbitrary mapper JSON and are routinely lists, so the first time two runs
     disagreed about a list-valued attribute the set raised. The third run was
     simply the first to disagree.

  2. NO ISOLATION. A single failing entity, relationship or derivation pass
     raised straight out of correlate.assemble() and aborted the fuse.

Both are fixed, and this file pins both. Isolation is tested with DELIBERATELY
broken input rather than the one bug that happened, because the requirement is
immunity to the next bug of this kind, not just to this one.

A degraded fuse must also be VISIBLE: errors are collected and store.py reports
the graph as PARTIAL. A fuse that silently drops data would be worse than one
that crashes.
"""
import ast
import datetime as _dt
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORE = os.path.join(ROOT, "modules/backend/services/fusion/store.py")

for _p in ("/app", os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402

from services.fusion import correlate, schema  # noqa: E402

_T0 = _dt.datetime(2026, 6, 16, 8, 0, 0, tzinfo=_dt.timezone.utc)


def _ts(h=0):
    return (_T0 + _dt.timedelta(hours=h)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _good_entities():
    h1, h2 = "asset:c1", "asset:c2"
    return [
        schema.Entity(id=h1, type="asset", label="ALDC02", first_seen=_ts(0)),
        schema.Entity(id=h2, type="asset", label="ALClient06", first_seen=_ts(1)),
        schema.Entity(id="acct:srv", type="account", label="adatumlab\\srv",
                      attrs={"_assets": [h1, h2]}, anomaly=5, severity="high",
                      first_seen=_ts(1), sources=["velociraptor"]),
    ]


def _assemble(contributions, **kw):
    return correlate.assemble("case_iso", contributions, ["run1"], **kw)


class TestTheRootCause(unittest.TestCase):
    """The exact live failure: two runs disagree about a list-valued attribute."""

    def test_conflicting_list_attribute_merges_instead_of_crashing(self):
        def run(users, src):
            return ([schema.Entity(id="asset:win11", type="asset", label="WIN11",
                                   sources=[src], attrs={"users": users})], [])

        errors = []
        g = _assemble([run(["alice", "bob"], "agentic"),
                       run(["alice", "carol"], "velociraptor")], errors=errors)

        e = g.entities.get("asset:win11")
        self.assertIsNotNone(e, "the entity must survive the conflicting merge")
        self.assertIn("conflict", e.flags)
        values = [o["value"] for o in e.attrs.get("users_observations", [])]
        self.assertIn(["alice", "bob"], values)
        self.assertIn(["alice", "carol"], values)
        self.assertEqual([], errors, "this is fixed at the source, not merely isolated")

    def test_a_repeated_list_value_is_not_recorded_twice(self):
        def run(users):
            return ([schema.Entity(id="asset:w", type="asset", label="w",
                                   sources=["r"], attrs={"users": users})], [])
        g = _assemble([run(["a"]), run(["b"]), run(["a"])])
        obs = g.entities["asset:w"].attrs["users_observations"]
        self.assertEqual(2, len(obs), obs)

    def test_union_tolerates_unhashable_elements(self):
        d = ["a"]
        schema._union(d, [["x"], ["x"], {"k": 1}, "a"])
        self.assertEqual(["a", ["x"], {"k": 1}], d)


class TestOneBadItemDoesNotLoseTheGraph(unittest.TestCase):

    def test_a_malformed_entity_is_skipped(self):
        errors = []
        ents = _good_entities() + [{"id": "not-an-entity"}]
        g = _assemble([(ents, [])], errors=errors)
        self.assertIn("acct:srv", g.entities, "the good entities must still be in the graph")
        self.assertEqual(1, len(errors), errors)
        self.assertIn("entity", errors[0]["where"])

    def test_a_malformed_contribution_is_skipped(self):
        errors = []
        g = _assemble(["not an (entities, relationships) pair",
                       (_good_entities(), [])], errors=errors)
        self.assertIn("acct:srv", g.entities)
        self.assertEqual(1, len(errors), errors)
        self.assertIn("contribution", errors[0]["where"])

    def test_a_relationship_that_cannot_be_hashed_is_skipped(self):
        errors = []
        good = schema.Relationship.from_dict(
            {"src": "asset:c1", "dst": "acct:srv", "kind": "logon"})
        bad = schema.Relationship.from_dict(
            {"src": ["asset:c1"], "dst": "acct:srv", "kind": "logon_bad"})
        g = _assemble([(_good_entities(), [bad, good])], errors=errors)
        kinds = {r.kind for r in g.relationships}
        self.assertIn("logon", kinds, "the good relationship must still be linked")
        self.assertEqual(1, len(errors), errors)
        self.assertIn("relationship", errors[0]["where"])

    def test_a_failing_pass_does_not_stop_the_passes_after_it(self):
        def boom(*_a, **_k):
            raise RuntimeError("synthetic pass failure")
        original = correlate._bridge_hashes
        correlate._bridge_hashes = boom
        self.addCleanup(setattr, correlate, "_bridge_hashes", original)

        errors = []
        g = _assemble([(_good_entities(), [])], errors=errors)

        self.assertTrue(any(e["where"] == "pass _bridge_hashes" for e in errors), errors)
        scored = [a for a in g.by_type("asset") if "risk_score" in a.attrs]
        self.assertTrue(scored, "_score_assets runs AFTER _bridge_hashes and must still run")

    def test_a_nested_list_in_assets_does_not_disable_a_whole_pass(self):
        # Isolation alone is not enough here. _assets_of() is shared by nearly
        # every derivation pass, so one entity whose _assets holds a nested list
        # would make the WHOLE pass fail -- e.g. _derive_findings, leaving the
        # case with no findings at all. Still "one error breaks everything",
        # just one level down. The bad asset id must be dropped, not fatal.
        ents = _good_entities() + [
            schema.Entity(id="proc:bad", type="process", label="x.exe",
                          attrs={"_assets": [["asset:c1"]]}, anomaly=25,
                          severity="high", first_seen=_ts(0), sources=["velociraptor"]),
        ]
        errors = []
        g = _assemble([(ents, [])], errors=errors)
        lost = [e for e in errors if e["where"].startswith("pass ")]
        self.assertEqual([], lost, "a whole derivation pass was lost to one entity")
        self.assertIn("acct:srv", g.entities)

    def test_a_nested_list_in_assets_does_not_break_host_asset_merging(self):
        # The same hazard in _resolve_host_assets: remapping an entity's asset
        # list hashed every element, so one nested list aborted the pass
        # half-way -- the asset node already merged, every entity's asset list
        # left pointing at the id that no longer exists.
        h = "asset:endpoint:host=ALDC02"
        ents = [
            schema.Entity(id="asset:c1", type="asset", label="ALDC02",
                          attrs={"hostname": "ALDC02"}, first_seen=_ts(0)),
            schema.Entity(id=h, type="asset", label="ALDC02", first_seen=_ts(0)),
            schema.Entity(id="acct:srv", type="account", label="srv",
                          attrs={"_assets": [h, ["nested"]]}, anomaly=5,
                          severity="high", first_seen=_ts(1), sources=["velociraptor"]),
        ]
        errors = []
        g = _assemble([(ents, [])], errors=errors)
        self.assertEqual([], [e for e in errors if e["where"] == "pass _resolve_host_assets"],
                         errors)
        self.assertIn("asset:c1", g.entities["acct:srv"].attrs["_assets"],
                      "the entity must follow its host to the canonical asset")

    def test_isolation_holds_when_the_caller_passes_no_errors_list(self):
        g = _assemble([(_good_entities() + [{"bad": True}], [])])
        self.assertIn("acct:srv", g.entities)

    def test_a_clean_fuse_records_nothing_and_is_unchanged(self):
        errors = []
        with_list = _assemble([(_good_entities(), [])], errors=errors)
        without = _assemble([(_good_entities(), [])])
        self.assertEqual([], errors)
        self.assertEqual(sorted(with_list.entities), sorted(without.entities))
        self.assertEqual(len(with_list.findings), len(without.findings))

    def test_error_detail_is_capped_so_a_broken_mapper_cannot_exhaust_memory(self):
        errors = []
        n = 500
        _assemble([(_good_entities() + [{"i": i} for i in range(n)], [])], errors=errors)
        cap = correlate._ERROR_DETAIL_CAP
        self.assertLessEqual(len(errors), cap + 1)
        self.assertEqual(n - cap, errors[-1].get("overflow"),
                         "failures past the cap must still be COUNTED")


class TestOneBadRunDoesNotLoseTheOthers(unittest.TestCase):
    """Behavioural, not structural: drive the real _fuse_case_locked with one run
    whose mapping raises, and prove the other runs still land in the graph.

    _record=False is the fuse's own dry-run mode: every case-log write and all
    persistence is skipped and the graph is returned straight after assembly, so
    this exercises the membership pass, the per-run generator and assemble()
    without touching a database.
    """

    @classmethod
    def setUpClass(cls):
        from unittest import mock
        from services.fusion import store
        cls.store, cls.mock = store, mock

    def _fuse(self, contribution_for_run, members=("good1", "bad", "good2")):
        store, mock = self.store, self.mock

        class _WS:
            AGENTIC_TYPES = {"velociraptor_collection", "memory"}
            def get_automation_run(self, rid):
                return {"run_id": rid, "name": f"run {rid}", "status": "completed",
                        "automation_type": "velociraptor_collection", "details": {}}
            def get_all_automation_runs(self):
                return []

        case = {"name": "iso", "min_severity": "informational", "time_window": None}
        with mock.patch.object(store, "_ws", lambda: _WS()), \
             mock.patch.object(store, "get_case", lambda _cid: case), \
             mock.patch.object(store, "_members_for_case", lambda _cid, _d=None: list(members)), \
             mock.patch.object(store, "_run_passes_gate", lambda _run, _d: True), \
             mock.patch.object(store, "load_baseline", lambda _key: None), \
             mock.patch.object(store, "_contribution_for_run", contribution_for_run):
            return store._fuse_case_locked("case_iso", _record=False)

    @staticmethod
    def _host(rid):
        return ([schema.Entity(id=f"asset:{rid}", type="asset", label=rid,
                               first_seen=_ts(0))], [])

    def test_the_other_runs_still_land_when_one_run_fails_to_map(self):
        def contribution_for_run(run, log=None, refetch=False):
            if run["run_id"] == "bad":
                raise TypeError("unhashable type: 'list'")   # the live failure
            return self._host(run["run_id"])

        g = self._fuse(contribution_for_run)
        self.assertIn("asset:good1", g.entities, "a run BEFORE the bad one was lost")
        self.assertIn("asset:good2", g.entities, "a run AFTER the bad one was lost")
        self.assertNotIn("asset:bad", g.entities)

    def test_a_fuse_where_every_run_fails_returns_an_empty_graph_not_an_exception(self):
        def contribution_for_run(run, log=None, refetch=False):
            raise RuntimeError("collector returned garbage")

        g = self._fuse(contribution_for_run)
        self.assertEqual({}, dict(g.entities))



class TestStoreReportsAPartialGraph(unittest.TestCase):
    """store.py must isolate each run and surface every failure it absorbed."""

    @classmethod
    def setUpClass(cls):
        with open(STORE, encoding="utf-8") as fh:
            cls.src = fh.read()
        cls.tree = ast.parse(cls.src)

    def _fn(self, name):
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
                return node
        self.fail(f"{name} not found in store.py")

    def test_mapping_a_run_is_inside_a_try(self):
        gen = self._fn("_contributions")
        guarded = False
        for node in ast.walk(gen):
            if isinstance(node, ast.Try):
                for inner in ast.walk(ast.Module(body=node.body, type_ignores=[])):
                    if (isinstance(inner, ast.Call)
                            and getattr(inner.func, "id", None) == "_contribution_for_run"):
                        guarded = True
        self.assertTrue(guarded, "one run failing to map would abort the whole fuse again")

    def test_assembly_errors_are_passed_in(self):
        self.assertIn("errors=_assembly_errors", self.src)

    def test_both_lists_exist_on_the_override_path_too(self):
        # They are read after the override/membership branches rejoin. Defined
        # inside one branch, the other path would raise NameError at completion.
        branch = self.src.index("if contributions_override is not None:")
        self.assertLess(self.src.index("_skipped: list = []"), branch)
        self.assertLess(self.src.index("_assembly_errors: list = []"), branch)

    def test_a_degraded_fuse_is_not_reported_as_success(self):
        # Anchored on the CALL, not the bare string: "Refusion complete" also
        # appears earlier in store.py inside a comment.
        i = self.src.index('log_case_event(case_id, "Refusion complete"')
        self.assertIn('"warning" if _degraded else "success"', self.src[i:i + 160])


if __name__ == "__main__":
    unittest.main(verbosity=2)
