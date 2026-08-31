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

from services.fusion import correlate, schema  # noqa: E402

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
