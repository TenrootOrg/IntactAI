"""Track C — fusion BEHAVIORAL tests: actually run correlate.assemble on built
contributions and assert engine behavior. The existing fusion suite only greps
source; nothing proved the engine's runtime behavior. Headline: fuse-twice ⇒
identical graph (idempotency), the property the whole incremental design rests on.

In-container (real package):
  docker exec intact_backend sh -lc \
    'PYTHONPATH=/app python3 /app/tests/test_fusion_behavioral.py'
"""
import datetime as _dt
import json
import os
import random
import sys
import unittest

for _p in ("/app", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# grpc is a backend-container dependency, not a test one, and importing
# anything under `services.` pulls it in via services/__init__.py. Stub it
# before that import or this file cannot be run standalone -- which is exactly
# how tests/run_tests.sh runs it.
import _optional_deps  # noqa: F401,E402

from services.fusion import correlate, render, schema  # noqa: E402

_T0 = _dt.datetime(2026, 6, 16, 8, 0, 0, tzinfo=_dt.timezone.utc)


def _ts(h=0):
    return (_T0 + _dt.timedelta(hours=h)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ev(locator):
    return schema.EvidenceRef(module="velociraptor", run_id="run1", locator=locator)


def _contribution():
    """A fixed, realistic single-run contribution (entities, relationships): two
    hosts, a shared account (→ cross-host finding), a suspicious process, and a
    shared suspicious hash (→ cross-host finding). Enough to exercise merge +
    several derivation passes."""
    h1, h2 = "asset:c1", "asset:c2"
    ents = [
        schema.Entity(id=h1, type="asset", label="ALDC02", first_seen=_ts(0)),
        schema.Entity(id=h2, type="asset", label="ALClient06", first_seen=_ts(1)),
        schema.Entity(id="acct:srv", type="account", label="adatumlab\\srv",
                      attrs={"_assets": [h1, h2]}, anomaly=5, severity="high",
                      first_seen=_ts(1), sources=["velociraptor"], evidence=[_ev("Logon/row=3")]),
        schema.Entity(id="proc:1", type="process", label="rubeus.exe",
                      attrs={"_assets": [h1], "ev_cmdline": "rubeus.exe asktgt"},
                      anomaly=25, severity="high", first_seen=_ts(0),
                      sources=["velociraptor"], evidence=[_ev("Sysmon/row=1")]),
        schema.Entity(id="ioc:h", type="ioc", label="a" * 64,
                      attrs={"_assets": [h1, h2], "ioc_kind": "hash"}, anomaly=10,
                      severity="high", first_seen=_ts(2), sources=["velociraptor"],
                      evidence=[_ev("Hashes/row=9")]),
    ]
    return [(ents, [])]


def _assemble(contribs=None, **kw):
    return correlate.assemble("case_t", contribs or _contribution(), ["run1"], **kw)


def _canon(g):
    """Order-independent canonical serialization for graph equality."""
    d = g.to_dict()
    return json.dumps({
        "entities": sorted((json.dumps(e, sort_keys=True, default=str)
                            for e in d.get("entities", {}).values()) if isinstance(d.get("entities"), dict)
                           else (json.dumps(e, sort_keys=True, default=str) for e in d.get("entities", []))),
        "findings": sorted(json.dumps(f, sort_keys=True, default=str) for f in d.get("findings", [])),
        "relationships": sorted(json.dumps(r, sort_keys=True, default=str) for r in d.get("relationships", [])),
    }, sort_keys=True)


class Idempotency(unittest.TestCase):
    def test_fuse_twice_identical(self):
        # THE headline test: same input, fresh graph each time ⇒ identical output.
        self.assertEqual(_canon(_assemble()), _canon(_assemble()))

    def test_findings_actually_derived(self):
        # guard the guard: if 0 findings, idempotency is vacuous.
        g = _assemble()
        self.assertGreater(len(g.findings), 0)
        self.assertTrue(any(f.kind == "cross_host" for f in g.findings))

    def test_incremental_seed_does_not_grow_evidence(self):
        # the +365 evidence-duplication bug class: re-fusing the SAME run onto the
        # stored graph as a seed must not append evidence again.
        g = _assemble()
        acct = g.entities["acct:srv"]
        n0 = len(acct.evidence)
        for _ in range(3):
            g = _assemble(seed=g)
        self.assertEqual(len(g.entities["acct:srv"].evidence), n0)

    def test_incremental_seed_matches_full_rebuild(self):
        # adding the same contribution to a seed ⇒ same graph as a clean rebuild.
        full = _assemble()
        seeded = _assemble(seed=_assemble())
        self.assertEqual(_canon(full), _canon(seeded))


class Determinism(unittest.TestCase):
    def test_entity_order_independent(self):
        base = _contribution()
        shuffled_ents = list(base[0][0])
        random.Random(1).shuffle(shuffled_ents)
        a = _assemble(base)
        b = _assemble([(shuffled_ents, [])])
        self.assertEqual(_canon(a), _canon(b))

    def test_risk_scores_stable_across_order(self):
        base = _contribution()
        s = list(base[0][0]); random.Random(9).shuffle(s)
        r1 = {e.id: e.attrs.get("risk_score") for e in _assemble(base).by_type("asset")}
        r2 = {e.id: e.attrs.get("risk_score") for e in _assemble([(s, [])]).by_type("asset")}
        self.assertEqual(r1, r2)


class Filters(unittest.TestCase):
    def test_window_drops_out_of_window_keeps_assets(self):
        win = {"start": _ts(0), "end": _ts(3)}
        # add a process far outside the window; assets always survive.
        ents = _contribution()[0][0] + [
            schema.Entity(id="proc:old", type="process", label="old.exe",
                          attrs={"_assets": ["asset:c1"]}, anomaly=25, severity="high",
                          first_seen="2020-01-01T00:00:00Z")]
        g = _assemble([(ents, [])], window=win)
        self.assertNotIn("proc:old", g.entities)          # out-of-window dropped
        self.assertIn("asset:c1", g.entities)             # asset kept regardless

    def test_min_severity_floor_drops_low(self):
        ents = _contribution()[0][0] + [
            schema.Entity(id="proc:low", type="process", label="benign.exe",
                          attrs={"_assets": ["asset:c1"]}, anomaly=0, severity="low",
                          first_seen=_ts(1))]
        g = _assemble([(ents, [])], min_severity="high")
        self.assertNotIn("proc:low", g.entities)          # below floor, dropped
        self.assertIn("asset:c1", g.entities)


class IdentityCrossHost(unittest.TestCase):
    """An actor whose account is written differently per host (DOMAIN\\u, u@domain,
    bare SAM) makes three separate account entities, so the per-entity cross-host rule
    misses the lateral movement. It must still surface via the identity cluster — but
    NOT when two different domains share a username stem (two different people)."""

    def _graph(self, forms):
        g = schema.FusionGraph(case_id="idxh")
        ents = []
        for i, (host, label) in enumerate(forms):
            aid = f"asset:h{i}"
            g.entities[aid] = schema.Entity(id=aid, type="asset", label=host)
            eid = f"account:asset:{aid}:{label}"
            g.entities[eid] = schema.Entity(
                id=eid, type="account", label=label, severity="medium", anomaly=5,
                first_seen=_ts(i), attrs={"_assets": [aid]}, sources=["velociraptor"])
            ents.append(eid)
        return g

    def _xhost(self, forms):
        g = self._graph(forms)
        correlate._identity_cross_host_findings(g)
        return [f for f in g.findings if f.kind == "cross_host"]

    def test_same_person_different_forms_surfaces(self):
        fs = self._xhost([("H1", "corp\\alice"), ("H2", "alice@corp.local")])
        self.assertGreaterEqual(len(fs), 1)
        self.assertIn("alice", fs[0].title.lower())

    def test_different_domains_same_stem_does_not_merge(self):
        # corpa\jsmith and corpb\jsmith are two DIFFERENT people — must NOT assert
        # lateral movement (this was a real false positive, caught and guarded)
        self.assertEqual(self._xhost([("H1", "corpa\\jsmith"), ("H2", "corpb\\jsmith")]), [])

    def test_single_host_identity_does_not_fire(self):
        self.assertEqual(self._xhost([("H1", "corp\\bob")]), [])


class TransportInputCap(unittest.TestCase):
    """The payload budget is derived from the MODEL's context window, but the Codex
    subscription CLI hard-rejects any request over 1 MiB of characters regardless of
    model size. MEASURED on this box: 1,000,125 chars OK (376,564 input tokens);
    1,100,000 chars -> 'Input exceeds the maximum length of 1048576 characters'.
    Without the clamp, a 1M-token model computes a ~2.9 MB payload and EVERY report
    fails."""

    def test_codex_transport_is_capped_under_1mib(self):
        from services.fusion import budget
        cap = budget.transport_cap_chars("codex-subscription")
        self.assertIsNotNone(cap)
        self.assertLess(cap, 1_048_576)          # strictly under the hard limit
        self.assertGreater(cap, 900_000)         # but not needlessly small

    def test_direct_api_providers_are_uncapped(self):
        from services.fusion import budget
        # only the CLI transport has a stdin size limit; HTTP providers do not
        self.assertIsNone(budget.transport_cap_chars("claude"))
        self.assertIsNone(budget.transport_cap_chars(""))

    def test_large_context_model_would_exceed_the_cli_limit(self):
        from services.fusion import budget
        chars, _tok = budget.adaptive_budget(1_000_000, 32_000)
        self.assertGreater(chars, 1_048_576)     # the failure this clamp prevents
        self.assertLess(budget.transport_cap_chars("codex-subscription"), chars)


class IdentitySuggestions(unittest.TestCase):
    """Cross-name identity links (jdoe <-> john.doe) were only ever computed when a case
    spanned >=2 infrastructure buckets — so for a Velociraptor-only engagement (one
    `endpoint` bucket, the commonest case) the analyst was NEVER offered the link, even
    though _match scores it 0.65. Within one bucket they must be SUGGESTIONS, never
    auto-merges: colleagues share hosts, and a wrong identity merge is an attribution
    error in a forensic report."""

    def _graph(self, pairs):
        g = schema.FusionGraph(case_id="idsug")
        for i, (host, label) in enumerate(pairs):
            aid = f"asset:h{i}"
            if aid not in g.entities:
                g.entities[aid] = schema.Entity(id=aid, type="asset", label=host)
            eid = f"account:asset:{aid}:{label}"
            g.entities[eid] = schema.Entity(
                id=eid, type="account", label=label, severity="low",
                first_seen=_ts(i), attrs={"_assets": [aid]}, sources=["velociraptor"])
        return g

    def _cands(self, pairs):
        from services.fusion import identities as idf
        g = self._graph(pairs)
        return [c for c in (idf.compute_candidates(g) or [])
                if c.get("kind") == "same_identity"]

    def test_single_bucket_cross_name_is_suggested(self):
        cs = self._cands([("H1", "corp\\jdoe"), ("H2", "corp\\john.doe")])
        self.assertGreaterEqual(len(cs), 1)          # previously ZERO

    def test_single_bucket_is_never_auto_merged(self):
        # even with shared-host corroboration it stays a suggestion
        cs = self._cands([("H1", "corp\\jdoe"), ("H1", "corp\\john.doe")])
        self.assertGreaterEqual(len(cs), 1)
        self.assertTrue(all(not c.get("auto") for c in cs))

    def test_identical_names_are_not_re_suggested(self):
        # same normalized name in one bucket is already handled by the account keys
        cs = self._cands([("H1", "corp\\alice"), ("H2", "corp\\alice")])
        self.assertEqual(cs, [])


class ReportedFromTheUI(unittest.TestCase):
    """Three issues reported from the live Case Analysis view."""

    def test_cross_host_finding_is_dated_from_the_same_identity(self):
        """A domain-qualified account gets a GLOBAL id and often carries no timestamp,
        while the per-host bare-SAM records for the same person are dated. The
        cross-host finding shipped with ts=null, which costs the analysis sequence and
        direction ("does not prove the initiating endpoint ... because ts is null")."""
        g = schema.FusionGraph(case_id="tsnull")
        for i in range(2):
            aid = f"asset:h{i}"
            g.entities[aid] = schema.Entity(id=aid, type="asset", label=f"H{i}")
        # undated domain-qualified account spanning both hosts
        g.entities["account:domain:corp\\gil"] = schema.Entity(
            id="account:domain:corp\\gil", type="account", label="corp\\gil",
            anomaly=5, severity="high", first_seen=None,
            attrs={"_assets": ["asset:h0", "asset:h1"]}, sources=["velociraptor"])
        # dated bare-SAM record for the SAME person
        g.entities["account:asset:h0:gil"] = schema.Entity(
            id="account:asset:h0:gil", type="account", label="gil", anomaly=1,
            first_seen="2026-03-18T20:31:06", attrs={"_assets": ["asset:h0"]},
            sources=["velociraptor"])
        correlate._cross_host_findings(g)
        xh = [f for f in g.findings if f.kind == "cross_host"]
        self.assertTrue(xh)
        self.assertTrue(all(f.ts for f in xh), "cross-host finding must not be undated")

    def test_collector_labels_are_canonical(self):
        """A Velociraptor collection and a Velociraptor hunt are one collector to the
        analyst; showing the internal split overstates coverage."""
        self.assertEqual(render._collectors(["agentic", "velociraptor", "memory"]),
                         ["velociraptor", "memory"])
        self.assertEqual(render._collectors(["velociraptor_hunt"]), ["velociraptor"])
        self.assertEqual(render._collectors([]), [])

    def test_host_risk_table_has_no_next_column(self):
        g = schema.FusionGraph(case_id="nx")
        g.entities["asset:a"] = schema.Entity(id="asset:a", type="asset", label="H0",
                                              severity="high",
                                              attrs={"risk_score": 60, "modules": ["agentic"]})
        md = render.risk_table_md(g)
        self.assertNotIn("| Next |", md)
        self.assertNotIn("_Next_", md)


class TimestampComparison(unittest.TestCase):
    """F2/F2b: timestamp widening + watermark staleness must compare INSTANTS, not
    lexicographic strings (a trailing 'Z' sorts after a fractional second)."""

    def test_wider_picks_fractional_later_as_max(self):
        z = "2026-06-16T12:00:00Z"
        frac = "2026-06-16T12:00:00.500Z"        # 0.5s LATER, but ".5" < "Z" as strings
        self.assertEqual(schema._wider(z, frac, want_min=False), frac)   # max = later
        self.assertEqual(schema._wider(z, frac, want_min=True), z)       # min = earlier

    def test_wider_single_and_blank(self):
        self.assertEqual(schema._wider("2026-01-01T00:00:00Z", None, want_min=True),
                         "2026-01-01T00:00:00Z")
        self.assertIsNone(schema._wider(None, None, want_min=False))

    def test_watermark_reopens_on_fractional_later(self):
        # same count, current 0.5s later -> stale verdict must re-open (True)
        self.assertTrue(correlate._wm_new_activity("1|2026-06-16T12:00:00Z",
                                                   "1|2026-06-16T12:00:00.500Z"))
        # fewer / not-later -> not stale
        self.assertFalse(correlate._wm_new_activity("2|2026-06-16T12:00:00Z",
                                                    "1|2026-06-16T12:00:00Z"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
