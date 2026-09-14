"""The fusion engine must not crash on ANY mapper output -- proved by fuzzing.

WHY THIS EXISTS. A live QA case was left with no graph at all because one run
carried a list where a hashable was expected ("TypeError: unhashable type:
'list'"). The fix for that one input is pinned in test_fusion_fault_isolation.py.
This file asks the harder question the operator actually cares about: is there
ANY input a collector could hand the engine that takes the fuse down?

It answers by construction rather than by example:

  1. EXHAUSTIVE single-field corruption: every Entity field, and the attribute
     keys the passes and renderers read, crossed with a catalogue of hostile
     values -- None, wrong scalar types, nested lists, dicts, sets, bytes,
     datetimes, NaN and inf, huge and control-character strings, 60-deep
     nesting, mixed-key dicts, arbitrary objects.
  2. SEEDED RANDOM multi-field corruption: 300 entities with up to four fields
     broken at once, sharing ids so the merge/conflict path is exercised.
  3. RELATIONSHIP-field and CONTRIBUTION-shape fuzzing, including a stream that
     dies half-way through.

For every generated graph the WHOLE consumer chain must survive, not just
assembly: every report renderer, chat, pruning, host filtering, JSON the way the
engine actually serialises it, and a save->load round trip. A graph that
assembles and then crashes the report is still a crashed fuse.

Nothing may silently disable a whole derivation pass either. One bad entity
costing _derive_findings would leave the case with no findings: the same
failure, only quieter.

Deterministic (fixed seed), so any failure reproduces exactly.
"""
import contextlib
import datetime as _dt
import json
import os
import random
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in ("/app", os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402

from services.fusion import correlate, render, schema, store  # noqa: E402

_T0 = _dt.datetime(2026, 6, 16, 8, 0, 0, tzinfo=_dt.timezone.utc)


def _ts(h=0):
    return (_T0 + _dt.timedelta(hours=h)).strftime("%Y-%m-%dT%H:%M:%SZ")


class _Weird:
    """An object no serialiser or comparison knows anything about."""
    def __repr__(self):
        return "<weird>"
    __str__ = __repr__


def _hostile_values():
    """Fresh objects every call: several of these are mutable."""
    deep = "leaf"
    for _ in range(60):
        deep = [deep]
    return {
        "None": None,
        "empty str": "",
        "zero": 0,
        "negative int": -1,
        "float": 1.5,
        "nan": float("nan"),
        "inf": float("inf"),
        "bool": True,
        "empty list": [],
        "list of str": ["x"],
        "nested list": [["nested"]],
        "list of dict": [{"k": 1}],
        "empty dict": {},
        "dict": {"k": ["v"]},
        "mixed-key dict": {1: "a", "b": 2},
        "set": {"a", "b"},
        "tuple": ("t", 1),
        "bytes": b"\x00\xff",
        "bytearray": bytearray(b"ab"),
        "datetime": _dt.datetime(2026, 1, 1, tzinfo=_dt.timezone.utc),
        "object": _Weird(),
        "huge str": "x" * 200_000,
        "control chars": "a\x00b‮c�\n\r\t",
        "deep nesting": deep,
        "epoch int": 1788000000,
    }


ENTITY_FIELDS = ("id", "type", "label", "attrs", "sources", "evidence", "anomaly",
                 "severity", "first_seen", "last_seen", "flags")
# Attribute keys the passes and renderers actually read.
ATTR_KEYS = ("_assets", "hostname", "title", "ev_cmdline", "users", "rule",
             "ioc_kind", "mitre", "risk_score")
SENTINELS = ("asset:c1", "asset:c2", "acct:srv", "proc:1")


def _good():
    return [
        schema.Entity(id="asset:c1", type="asset", label="h1",
                      attrs={"hostname": "h1"}, first_seen=_ts(0)),
        schema.Entity(id="asset:c2", type="asset", label="h2",
                      attrs={"hostname": "h2"}, first_seen=_ts(1)),
        schema.Entity(id="acct:srv", type="account", label="srv",
                      attrs={"_assets": ["asset:c1", "asset:c2"]}, anomaly=5,
                      severity="high", first_seen=_ts(1), sources=["velociraptor"]),
        schema.Entity(id="proc:1", type="process", label="rubeus.exe",
                      attrs={"_assets": ["asset:c1"], "ev_cmdline": "rubeus.exe asktgt"},
                      anomaly=40, severity="critical", first_seen=_ts(0),
                      sources=["velociraptor"],
                      evidence=[schema.EvidenceRef(module="velociraptor", run_id="r",
                                                   locator="row=1")]),
    ]


def _victim(**over):
    kw = dict(id="proc:victim", type="process", label="x.exe",
              attrs={"_assets": ["asset:c1"], "ev_cmdline": "x.exe -a"},
              anomaly=25, severity="high", first_seen=_ts(0), last_seen=_ts(2),
              sources=["velociraptor"], flags=["suspicious"])
    kw.update(over)
    return schema.Entity(**kw)


CONSUMERS = {
    "report": lambda g: render.report(g),
    "facts_md": lambda g: render.facts_md(g),
    "narrative_md": lambda g: render.narrative_md(g),
    "risk_table_md": lambda g: render.risk_table_md(g),
    "scope": lambda g: render.scope(g),
    "timeline": lambda g: render.timeline(g),
    "report_header": lambda g: render.report_header(g),
    "zoom_targets": lambda g: render.zoom_targets(g),
    "suspicious_timeframes_md": lambda g: render.suspicious_timeframes_md(g),
    "chat_subgraph": lambda g: render.chat_subgraph(g, "what happened on h1?"),
    # store.py:1913 json.dumps(render.distilled(...)) -- no default=str there
    "distilled as json": lambda g: json.dumps(render.distilled(g)),
    "pruned": lambda g: g.pruned(max_entities=2).to_dict(),
    # the sidecar is written with default=str (store.py _write_graph_sidecar)
    "sidecar json": lambda g: json.dumps(g.to_dict(), default=str),
    "save->load": lambda g: schema.FusionGraph.from_dict(
        json.loads(json.dumps(g.to_dict(), default=str))),
    "host filter": lambda g: store._filter_graph_by_hosts(g, ["h1"]),
}


def _run_chain(contributions, required_rel_kinds=()):
    """Assemble, then drive every consumer. Returns a list of failure strings."""
    errs = []
    try:
        g = correlate.assemble("case_fz", contributions, ["run1"], errors=errs)
    except Exception as ex:                                   # noqa: BLE001
        return [f"assemble raised {type(ex).__name__}: {str(ex)[:120]}"]
    fails = []
    lost = sorted({str(e.get("where")) for e in errs
                   if str(e.get("where", "")).startswith("pass ")})
    if lost:
        fails.append(f"lost whole pass(es): {', '.join(lost)}")
    missing = [s for s in SENTINELS if s not in g.entities]
    if missing:
        fails.append(f"good entities lost: {missing}")
    kinds = {getattr(r, "kind", None) for r in g.relationships}
    for k in required_rel_kinds:
        if k not in kinds:
            fails.append(f"good relationship {k!r} lost")
    for name, fn in CONSUMERS.items():
        try:
            fn(g)
        except Exception as ex:                               # noqa: BLE001
            fails.append(f"{name}: {type(ex).__name__}: {str(ex)[:90]}")
    return fails


class _Report(unittest.TestCase):
    def _report(self, failures):
        if failures:
            shown = "\n  ".join(failures[:60])
            more = f"\n  ... and {len(failures) - 60} more" if len(failures) > 60 else ""
            self.fail(f"{len(failures)} crash path(s):\n  {shown}{more}")


class TestTheHarnessItself(_Report):
    def test_a_clean_case_passes_every_consumer(self):
        # If this fails the harness is broken, and every other verdict is noise.
        self._report(_run_chain([(_good(), [])]))


class TestNoSingleCorruptFieldCanCrashTheFuse(_Report):

    def test_every_entity_field_x_every_hostile_value(self):
        failures = []
        for field in ENTITY_FIELDS:
            for vname in _hostile_values():
                v1 = _victim(**{field: _hostile_values()[vname]})
                v2 = _victim(**{field: _hostile_values()[vname]})
                if field != "attrs":
                    # Same id, conflicting list-valued attribute: forces the
                    # merge path that took the live case down.
                    v1.attrs["users"] = ["alice"]
                    v2.attrs["users"] = ["carol"]
                for f in _run_chain([(_good() + [v1], []), ([v2], [])]):
                    failures.append(f"Entity.{field} = {vname}: {f}")
        self._report(failures)

    def test_every_attribute_the_engine_reads_x_every_hostile_value(self):
        failures = []
        for key in ATTR_KEYS:
            for vname in _hostile_values():
                attrs = {"_assets": ["asset:c1"], "ev_cmdline": "x.exe -a"}
                attrs[key] = _hostile_values()[vname]
                for f in _run_chain([(_good() + [_victim(attrs=attrs)], [])]):
                    failures.append(f"attrs[{key!r}] = {vname}: {f}")
        self._report(failures)


class TestRandomMultiFieldCorruption(_Report):

    def test_300_randomly_broken_entities_in_one_case(self):
        rng = random.Random(20260914)
        names = list(_hostile_values())
        fields = list(ENTITY_FIELDS) + [f"attrs.{k}" for k in ATTR_KEYS]
        contributions, batch = [(_good(), [])], []
        for _ in range(300):
            kw = {}
            attrs = {"_assets": ["asset:c1"], "ev_cmdline": "x.exe -a"}
            for field in rng.sample(fields, rng.randint(1, 4)):
                val = _hostile_values()[rng.choice(names)]
                if field.startswith("attrs."):
                    if isinstance(attrs, dict):
                        attrs[field[len("attrs."):]] = val
                elif field == "attrs":
                    attrs = val
                else:
                    kw[field] = val
            kw.setdefault("id", f"proc:r{rng.randint(0, 40)}")   # collisions force merges
            kw["attrs"] = attrs
            batch.append(_victim(**kw))
            if len(batch) == 50:
                contributions.append((batch, []))
                batch = []
        if batch:
            contributions.append((batch, []))
        self._report(_run_chain(contributions))


class TestRelationshipsCannotCrashTheFuse(_Report):

    def test_every_relationship_field_x_every_hostile_value(self):
        failures = []
        for field in ("src", "dst", "kind", "attrs", "sources", "ts"):
            for vname in _hostile_values():
                d = {"src": "asset:c1", "dst": "acct:srv", "kind": "logon_bad",
                     "attrs": {}, "sources": ["velociraptor"], "ts": _ts(1)}
                d[field] = _hostile_values()[vname]
                bad = schema.Relationship(**d)
                ok = schema.Relationship(src="asset:c1", dst="acct:srv", kind="logon_ok")
                for f in _run_chain([(_good(), [bad, ok])], required_rel_kinds=("logon_ok",)):
                    failures.append(f"Relationship.{field} = {vname}: {f}")
        self._report(failures)


class TestContributionShapesCannotCrashTheFuse(_Report):

    def test_hostile_contribution_shapes(self):
        shapes = {
            "None": None,
            "int": 7,
            "str": "garbage",
            "one-tuple": (_good(),),
            "three-tuple": (_good(), [], "extra"),
            "(None, None)": (None, None),
            "([None], [None])": ([None], [None]),
            "(dict, dict)": ({"a": 1}, {"b": 2}),
            "(entities, 'not a list')": (_good(), "not a list"),
            "(object, object)": (_Weird(), _Weird()),
        }
        failures = []
        for name, shape in shapes.items():
            for f in _run_chain([(_good(), []), shape]):
                failures.append(f"contribution {name}: {f}")
        self._report(failures)

    def test_a_stream_that_dies_half_way_keeps_what_it_already_yielded(self):
        def stream():
            yield (_good(), [])
            raise RuntimeError("collector stream broke mid-iteration")
        self._report([f"dying stream: {f}" for f in _run_chain(stream())])



def _junk_contribution():
    """Every entity field broken every way, plus relationships to match."""
    ents = list(_good())
    for field in ENTITY_FIELDS:
        for vname in _hostile_values():
            kw = {field: _hostile_values()[vname]}
            if field != "id":
                kw["id"] = f"proc:junk:{field}:{vname}"
            ents.append(_victim(**kw))
    rels = [schema.Relationship(src=v, dst="acct:srv", kind="junk")
            for v in _hostile_values().values()]
    rels.append(schema.Relationship(src="asset:c1", dst="acct:srv", kind="logon_ok"))
    return ents, rels


class TestTheWholeFuseSurvives(unittest.TestCase):
    """The REAL _fuse_case_locked with _record=True: report rendering, host
    filtering, pruning and the database write all run. Only storage and the
    network are faked, in memory.

    Everything above proves assemble() and the renderers in isolation. This
    proves the thing the operator sees: a fuse that is handed a failing run and
    a run full of garbage still finishes, still saves a graph, still writes a
    report, and says it is PARTIAL rather than claiming success.
    """

    def _fuse(self, contribution_for_run, *extra_patches):
        from unittest import mock
        llm_sim = store.llm_sim     # the module store calls; another test may swap sys.modules
        events, sidecars, statuses = [], [], []

        class _WS:
            AGENTIC_TYPES = {"velociraptor_collection"}
            def get_automation_run(self, rid):
                return {"run_id": rid, "name": f"run {rid}", "status": "completed",
                        "automation_type": "velociraptor_collection", "details": {}}
            def get_all_automation_runs(self):
                return []
            def update_run_status(self, rid, status, **kw):
                statuses.append((rid, status, kw))
                return True

        case = {"name": "fz", "min_severity": "informational", "time_window": None,
                "excluded_hosts": ["h2"], "disposition_checklist": [{"q": "kept"}]}
        patches = [
            mock.patch.object(store, "_ws", lambda: _WS()),
            mock.patch.object(store, "get_case", lambda _c: case),
            mock.patch.object(store, "_members_for_case",
                              lambda _c, _d=None: ["good1", "bad", "junk", "good2"]),
            mock.patch.object(store, "_run_passes_gate", lambda _r, _d: True),
            mock.patch.object(store, "load_baseline", lambda _k: None),
            mock.patch.object(store, "_contribution_for_run", contribution_for_run),
            mock.patch.object(store, "log_case_event",
                              lambda _cid, action, status="ok", detail="", **_kw:
                              events.append((action, status, detail))),
            mock.patch.object(store, "_write_graph_sidecar",
                              lambda _cid, gd: sidecars.append(gd) or True),
            mock.patch.object(store, "_merge_case_details", lambda *a, **k: None),
            mock.patch.object(store, "_mutate_list_field", lambda *a, **k: None),
            mock.patch.object(store, "_configured_fusion_model", lambda: (None, None, "simulated")),
            mock.patch.object(store, "_llm_payload_budget", lambda _d: (1000, 100_000)),
            mock.patch.object(store, "_llm_identity_budget", lambda _d: None),
            mock.patch.object(store, "_effective_output_cap", lambda _d: 4000),
            mock.patch.object(store, "_raw_payload_size", lambda _run: 0),
            mock.patch.object(llm_sim, "_use_real", lambda: False),
        ]
        try:
            from services.fusion import kb
            patches += [mock.patch.object(kb, "enrich", lambda *a, **k: None),
                        mock.patch.object(kb, "index_case_entities", lambda *a, **k: None)]
        except Exception:                                     # noqa: BLE001
            pass                  # store's kb call is already best-effort
        with contextlib.ExitStack() as stack:
            for p in patches + list(extra_patches):
                stack.enter_context(p)
            g = store._fuse_case_locked("case_fz", _record=True, allow_llm=False)
        return g, events, sidecars, statuses

    @staticmethod
    def _runs(run, log=None, refetch=False):
        rid = run["run_id"]
        if rid == "bad":
            raise TypeError("unhashable type: 'list'")         # the live failure
        if rid == "junk":
            return _junk_contribution()
        return ([schema.Entity(id=f"asset:{rid}", type="asset", label=rid,
                               attrs={"hostname": rid}, first_seen=_ts(0))], [])

    def _assert_finished_partial(self, g, events, sidecars, statuses):
        self.assertIn("asset:good1", g.entities, "a good run before the failures was lost")
        self.assertIn("asset:good2", g.entities, "a good run after the failures was lost")
        self.assertEqual(1, len(sidecars), "the graph was not saved")
        self.assertTrue((sidecars[0].get("entities") or {}), "an empty graph was saved")
        done = [s for s in statuses if s[1] == "completed"]
        self.assertEqual(1, len(done), "the case was never marked completed")
        self.assertIsInstance(done[0][2]["details"]["report_md"], str)
        self.assertTrue(done[0][2]["details"]["report_md"], "no report was written")
        complete = [e for e in events if e[0] == "Refusion complete"]
        self.assertEqual(1, len(complete), f"no completion line: {[e[0] for e in events]}")
        self.assertEqual("warning", complete[0][1],
                         "a degraded fuse must not be reported as success")
        self.assertIn("PARTIAL", complete[0][2])

    def test_a_failing_run_and_a_run_full_of_garbage_still_finish(self):
        self._assert_finished_partial(*self._fuse(self._runs))

    def test_a_crash_inside_report_rendering_does_not_lose_the_fuse(self):
        from unittest import mock
        llm_sim = store.llm_sim     # the module store calls; another test may swap sys.modules
        boom = mock.patch.object(llm_sim, "generate_report",
                                 side_effect=RuntimeError("renderer exploded"))
        g, events, sidecars, statuses = self._fuse(self._runs, boom)
        self._assert_finished_partial(g, events, sidecars, statuses)
        details = [s for s in statuses if s[1] == "completed"][0][2]["details"]
        self.assertTrue(details["report_dirty"],
                        "a report that failed must be rebuilt next time, not trusted")

    def test_a_crash_while_pruning_still_saves_the_graph(self):
        from unittest import mock
        boom = mock.patch.object(schema.FusionGraph, "pruned",
                                 side_effect=RuntimeError("pruning exploded"))
        self._assert_finished_partial(*self._fuse(self._runs, boom))

    def test_a_crash_while_filtering_hosts_still_reports_on_the_whole_graph(self):
        from unittest import mock
        boom = mock.patch.object(store, "_filter_graph_by_hosts",
                                 side_effect=RuntimeError("host filter exploded"))
        self._assert_finished_partial(*self._fuse(self._runs, boom))


if __name__ == "__main__":
    unittest.main(verbosity=2)
