"""Portable case bundles: what must survive a move between appliances.

A bundle crosses an air gap on removable media and lands on a machine that has
none of the source's context — no Velociraptor holding the original flows, no
VolWeb holding the yara hits, and quite possibly cases of its own using ids that
collide with the incoming ones. Every test here is one of those realities:

  - the COLLECTED DATA has to travel, or the imported case can be looked at but
    never recomputed, and the forward-compatibility promise (a future release
    re-fuses an old case with its own engine) is empty;
  - the source's ids must never be reused, because `<type>_<epoch_ms>` collides
    between appliances and the previous implementation's INSERT OR REPLACE
    silently overwrote whatever the destination already had;
  - a corrupt or truncated copy must be caught while the destination is still
    untouched — verification before the first write, not after;
  - a failure half-way must leave NOTHING, because a case that looks complete
    and is quietly missing evidence is worse than an obvious failure.

case_bundle reaches its collaborators through _store()/_ws(), so the REAL module
runs here against fakes and a tmpdir — no Flask, no SQLite, no docker.
"""

import json
import hashlib
import os
import shutil
import sys
import tempfile
import types
import unittest
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, "modules/backend")
sys.path.insert(0, BACKEND)

# services/__init__.py pulls in the entire backend (grpc, elasticsearch, the
# Velociraptor client...), none of which a dev box or CI has. Bind the package to
# its directory WITHOUT executing that __init__, so the two leaf modules under
# test import for real: case_bundle reaches everything else through _store()/_ws(),
# and archive_guard depends on nothing but the stdlib.
_svc = types.ModuleType("services")
_svc.__path__ = [os.path.join(BACKEND, "services")]
sys.modules["services"] = _svc

import services.fusion.case_bundle as cb  # noqa: E402


# ── fakes ────────────────────────────────────────────────────────────────────
class FakeWS:
    """workflow_service: an in-memory row store with the real id shape."""

    AGENTIC_TYPES = {"velociraptor_collection", "memory", "aws_scan",
                     "velociraptor_upload", "timesketch", "velociraptor_hunt"}

    def __init__(self):
        self.rows = {}
        self.logs = []
        self._n = 1_755_512_400_000

    # -- id minting (same shape as the real _next_run_id) --
    def _next_run_id(self, automation_type):
        self._n += 1
        return f"{automation_type}_{self._n}"

    def create_automation_run(self, automation_type, name, details=None, case_id=None):
        rid = self._next_run_id(automation_type)
        self.rows[rid] = {"run_id": rid, "automation_type": automation_type,
                          "name": name, "details": details or {}, "status": "pending",
                          "case_id": case_id, "created_at": "2026-08-23T00:00:00"}
        return rid

    def get_automation_run(self, run_id):
        return self.rows.get(run_id)

    def get_all_automation_runs(self):
        return list(self.rows.values())

    def get_automation_runs_by_case(self, case_id):
        return [r for r in self.rows.values() if r.get("case_id") == case_id]

    def update_run_status(self, run_id, status, progress=None, error=None,
                          details=None, force=False):
        r = self.rows.get(run_id)
        if not r:
            return
        r["status"] = status
        if details:
            r["details"] = {**(r.get("details") or {}), **details}

    def add_log_to_run(self, run_id, msg, level="info"):
        self.logs.append((run_id, level, msg))

    def mutate_run_details(self, run_id, mutator):
        r = self.rows.get(run_id)
        if r:
            d = r.get("details") or {}
            mutator(d)
            r["details"] = d


class FakeStore:
    CASE_TYPE = "case"
    BASELINE_TYPE = "fusion_baseline"

    def __init__(self, ws, graph_dir):
        self.ws = ws
        self.graph_dir = graph_dir
        self.events = []

    def _graph_path(self, case_id):
        return os.path.join(self.graph_dir, f"{case_id}.json")

    def _write_graph_sidecar(self, case_id, g):
        os.makedirs(self.graph_dir, exist_ok=True)
        with open(self._graph_path(case_id), "w") as f:
            json.dump(g, f)
        return True

    def _delete_graph_sidecar(self, case_id):
        try:
            os.remove(self._graph_path(case_id))
        except FileNotFoundError:
            pass

    def _members_for_case(self, case_id, d=None):
        tagged = [r["run_id"] for r in self.ws.get_automation_runs_by_case(case_id)
                  if r.get("automation_type") in self.ws.AGENTIC_TYPES]
        legacy = [r for r in ((d or {}).get("member_run_ids") or []) if r not in tagged]
        return tagged + legacy

    def is_system_case(self, case_id):
        d = (self.ws.rows.get(case_id) or {}).get("details") or {}
        return bool(d.get("is_system") or d.get("name") == "System")

    def log_case_event(self, case_id, action, status="ok", detail="", **kw):
        self.events.append({"case_id": case_id, "action": action,
                            "status": status, "detail": detail})


class BundleTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="casebundle-")
        self.ws = FakeWS()
        self.store = FakeStore(self.ws, os.path.join(self.tmp, "fusion_graphs"))

        cb._store = lambda: self.store
        cb._ws = lambda: self.ws
        # Every path the module touches, redirected into the tmpdir.
        cb.EXPORT_DIR = os.path.join(self.tmp, "case_exports")
        cb.DOWNLOAD_DIRS = (os.path.join(self.tmp, "downloads"),)
        cb.DOWNLOAD_WRITE_DIR = os.path.join(self.tmp, "downloads")
        cb.AWS_DIRS = (os.path.join(self.tmp, "aws_runs"),)
        cb.AWS_WRITE_DIR = os.path.join(self.tmp, "aws_runs")
        # Only the two row-level seams are faked; the REAL _unwind runs, because
        # what it gets wrong (order, what it forgets to remove) is the whole risk.
        self.saved_rows = []
        cb._save_row = self._save_row
        cb._delete_row = lambda rid: self.ws.rows.pop(rid, None)

    def _save_row(self, row):
        self.saved_rows.append(row["run_id"])
        self.ws.rows[row["run_id"]] = row

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- fixture builders ------------------------------------------------------
    def make_case(self, name="GOOGLE IR", *, runs=2, payloads=True, graph=True,
                  baseline=True, aws=False, inline_graph=False):
        case_id = self.ws.create_automation_run("case", f"Case — {name}", details={})
        member_ids = []
        for i in range(runs):
            rid = self.ws.create_automation_run(
                "velociraptor_collection", f"Agentic {i}",
                details={"client_name": f"HOST{i}", "hunt_id": f"H.{i}"},
                case_id=case_id)
            member_ids.append(rid)
            if payloads:
                d = os.path.join(cb.DOWNLOAD_WRITE_DIR, rid)
                os.makedirs(d, exist_ok=True)
                with open(os.path.join(d, "raw_results.json"), "w") as f:
                    json.dump({"Windows.System.Pslist": [
                        {"Name": "evil.exe", "Pid": 4000 + i, "run": rid}] * 40}, f)
        if aws:
            arid = self.ws.create_automation_run("aws_scan", "AWS", details={},
                                                 case_id=case_id)
            member_ids.append(arid)
            os.makedirs(cb.AWS_WRITE_DIR, exist_ok=True)
            with open(os.path.join(cb.AWS_WRITE_DIR, f"{arid}.json"), "w") as f:
                json.dump({"findings": [{"title": "public bucket", "run": arid}]}, f)
        if baseline:
            self.ws.create_automation_run(
                "fusion_baseline", "Baseline — env",
                details={"env_key": "env-1", "source_case": case_id,
                         "fingerprint": {"sigma_titles": ["Known IT tool"]}})

        first = member_ids[0] if member_ids else "none"
        det = {
            "name": name,
            "min_severity": "medium",
            "customer_name": "GOOGLE",
            "report_md": "# Incident report\n\nEvidence from " + first,
            "chat_messages": [{"role": "user", "text": "what happened on " + first}],
            "dispositions": [{"target": "finding:1", "verdict": "benign",
                              "reason": "known admin", "run": first}],
            "timeline_validations": [{"finding_id": f"f:{first}:1",
                                      "status": "real"}],
            "manual_timeline_events": [{"finding_id": "manual:abc", "title": "IR call"}],
            "disposition_checklist": [{"q": "reimaged?", "status": "accepted"}],
            "identity_links": [{"decision": "confirm", "members": ["acct:a", "acct:b"]}],
            "member_run_ids": member_ids,
            "fused_run_ids": list(member_ids),
            "report_run_ids": list(member_ids),
            "graph_counts": {"entities": 18749, "findings": 94},
            "activity_log": [{"action": "Refusion", "detail": "customer-side audit"}],
            "auto_fuse_incomplete": False,
        }
        g = {"case_id": case_id, "run_ids": list(member_ids),
             "entities": {"asset:endpoint:c1": {"type": "asset", "label": "HOST0",
                                                "evidence": [{"run_id": first}]}},
             "relationships": [], "findings": [{"id": "finding:1", "title": "SIGMA: x",
                                                "entity_ids": ["asset:endpoint:c1"]}]}
        if inline_graph:
            det["fusion_graph"] = g
        elif graph:
            self.store._write_graph_sidecar(case_id, g)
        self.ws.rows[case_id]["details"] = det
        self.ws.rows[case_id]["status"] = "completed"
        return case_id, member_ids

    def export(self, case_id):
        res = cb.export_case_bundle(case_id)
        self.assertTrue(os.path.exists(res["bundle_path"]))
        return res["bundle_path"], res


# ── the round trip ───────────────────────────────────────────────────────────
class TestRoundTrip(BundleTestBase):
    def test_export_then_import_reproduces_the_case(self):
        case_id, members = self.make_case(runs=2, aws=True)
        path, exp = self.export(case_id)
        res = cb.import_case_bundle(path)

        new = self.ws.rows[res["case_id"]]["details"]
        self.assertEqual(new["name"], "GOOGLE IR (imported)")   # same box: de-duped
        self.assertEqual(new["customer_name"], "GOOGLE")
        self.assertEqual(new["min_severity"], "medium")
        self.assertEqual(len(new["dispositions"]), 1)
        self.assertEqual(len(new["timeline_validations"]), 1)
        self.assertEqual(len(new["manual_timeline_events"]), 1)
        self.assertEqual(len(new["disposition_checklist"]), 1)
        self.assertEqual(len(new["identity_links"]), 1)
        self.assertIn("# Incident report", new["report_md"])
        self.assertEqual(len(new["chat_messages"]), 1)
        self.assertEqual(res["runs_imported"], 3)               # 2 agentic + 1 aws
        self.assertEqual(res["baselines_imported"], 1)

    def test_collected_payloads_travel_and_land_where_fusion_reads_them(self):
        """Without this the imported case can never be re-fused — the whole point."""
        case_id, members = self.make_case(runs=2)
        path, _ = self.export(case_id)
        res = cb.import_case_bundle(path)

        new_members = self.ws.rows[res["case_id"]]["details"]["member_run_ids"]
        self.assertEqual(len(new_members), 2)
        for rid in new_members:
            fp = os.path.join(cb.DOWNLOAD_WRITE_DIR, rid, "raw_results.json")
            self.assertTrue(os.path.exists(fp), f"no collected data for {rid}")
            with open(fp) as f:
                rows = json.load(f)["Windows.System.Pslist"]
            self.assertEqual(rows[0]["Name"], "evil.exe")

    def test_aws_findings_travel(self):
        case_id, _ = self.make_case(runs=1, aws=True)
        path, _ = self.export(case_id)
        res = cb.import_case_bundle(path)
        found = [rid for rid in self.ws.rows[res["case_id"]]["details"]["member_run_ids"]
                 if os.path.exists(os.path.join(cb.AWS_WRITE_DIR, f"{rid}.json"))]
        self.assertEqual(len(found), 1)

    def test_graph_lands_in_a_sidecar_not_inline_in_details(self):
        """An inline graph is the 8-18s-per-call regression the sidecar split fixed;
        the previous importer left every imported case that way forever."""
        case_id, _ = self.make_case()
        path, _ = self.export(case_id)
        res = cb.import_case_bundle(path)
        self.assertTrue(os.path.exists(self.store._graph_path(res["case_id"])))
        self.assertNotIn("fusion_graph", self.ws.rows[res["case_id"]]["details"])

    def test_baselines_travel_and_point_at_the_new_case(self):
        """Environment-scope dispositions live in baselines; leaving them behind
        silently un-suppresses known-good activity on the destination."""
        case_id, _ = self.make_case()
        path, _ = self.export(case_id)
        res = cb.import_case_bundle(path)
        bl = [r for r in self.ws.rows.values()
              if r["automation_type"] == "fusion_baseline"
              and (r["details"] or {}).get("source_case") == res["case_id"]]
        self.assertEqual(len(bl), 1)
        self.assertEqual(bl[0]["details"]["fingerprint"]["sigma_titles"], ["Known IT tool"])
        self.assertIsNone(bl[0].get("case_id"), "a baseline is not a case member")

    def test_a_case_with_no_runs_still_round_trips(self):
        case_id, _ = self.make_case(runs=0, payloads=False, baseline=False)
        path, _ = self.export(case_id)
        res = cb.import_case_bundle(path)
        self.assertEqual(res["runs_imported"], 0)
        self.assertEqual(self.ws.rows[res["case_id"]]["details"]["name"],
                         "GOOGLE IR (imported)")

    def test_legacy_inline_graph_is_normalised_into_the_bundle(self):
        case_id, _ = self.make_case(graph=False, inline_graph=True)
        path, _ = self.export(case_id)
        with zipfile.ZipFile(path) as zf:
            self.assertIn("graph.json", zf.namelist())
            case_doc = json.loads(zf.read("case.json"))
        self.assertNotIn("fusion_graph", case_doc["details"])
        res = cb.import_case_bundle(path)
        self.assertTrue(os.path.exists(self.store._graph_path(res["case_id"])))


# ── nothing system-wide travels ──────────────────────────────────────────────
class TestWhatMustNotTravel(BundleTestBase):
    def test_the_customers_activity_log_stays_behind(self):
        case_id, _ = self.make_case()
        path, _ = self.export(case_id)
        with zipfile.ZipFile(path) as zf:
            self.assertNotIn("activity_log", json.loads(zf.read("case.json"))["details"])
        res = cb.import_case_bundle(path)
        self.assertNotIn("activity_log", self.ws.rows[res["case_id"]]["details"])

    def test_the_import_is_recorded_in_the_new_cases_fresh_log(self):
        case_id, _ = self.make_case()
        path, _ = self.export(case_id)
        res = cb.import_case_bundle(path)
        imported = [e for e in self.store.events
                    if e["case_id"] == res["case_id"] and e["action"] == "Import case"]
        self.assertTrue(imported)
        self.assertIn("run(s)", imported[0]["detail"])

    def test_default_and_system_flags_are_stripped(self):
        case_id, _ = self.make_case()
        self.ws.rows[case_id]["details"]["is_default"] = True
        path, _ = self.export(case_id)
        res = cb.import_case_bundle(path)
        d = self.ws.rows[res["case_id"]]["details"]
        self.assertNotIn("is_default", d)
        self.assertNotIn("is_system", d)

    def test_the_system_workspace_cannot_be_exported(self):
        case_id = self.ws.create_automation_run("case", "Case — System",
                                                details={"name": "System",
                                                         "is_system": True})
        with self.assertRaises(cb.BundleError) as ctx:
            cb.plan_export(case_id)
        self.assertIn("System", str(ctx.exception))

    def test_crash_loop_marker_does_not_travel(self):
        """auto_fuse_incomplete describes the SOURCE appliance running out of
        memory; carried over it would refuse to auto-fuse on a healthy box."""
        case_id, _ = self.make_case()
        self.ws.rows[case_id]["details"]["auto_fuse_incomplete"] = True
        path, _ = self.export(case_id)
        res = cb.import_case_bundle(path)
        self.assertNotIn("auto_fuse_incomplete", self.ws.rows[res["case_id"]]["details"])


# ── run ids are never reused ─────────────────────────────────────────────────
class TestIdRemap(BundleTestBase):
    def test_no_source_id_survives_anywhere_in_the_imported_case(self):
        case_id, members = self.make_case(runs=2, aws=True)
        path, _ = self.export(case_id)
        res = cb.import_case_bundle(path)

        row = json.loads(json.dumps(self.ws.rows[res["case_id"]], default=str))
        prov = row["details"].pop("imported")          # provenance, asserted below
        blob = json.dumps(row, default=str)
        with open(self.store._graph_path(res["case_id"])) as f:
            blob += f.read()
        for rid in self.ws.rows[res["case_id"]]["details"]["member_run_ids"]:
            blob += json.dumps(self.ws.rows[rid], default=str)
        for old in [case_id] + list(members):
            self.assertNotIn(old, blob, f"source id {old} leaked into the imported case")
        # The one place a source id is kept on purpose: an inert provenance record
        # so support can answer "which case on which appliance did this come from?".
        self.assertEqual(prov["source_case_id"], case_id)
        self.assertIn("from_version", prov)
        self.assertIn("exported_at", prov)

    def test_references_are_rewritten_not_merely_dropped(self):
        """The report, chat, dispositions and graph all name run ids; a rewrite
        that loses them leaves dangling references pointing at nothing."""
        case_id, members = self.make_case(runs=1)
        path, _ = self.export(case_id)
        res = cb.import_case_bundle(path)
        new = self.ws.rows[res["case_id"]]["details"]
        new_rid = new["member_run_ids"][0]
        self.assertIn(new_rid, new["report_md"])
        self.assertIn(new_rid, new["chat_messages"][0]["text"])
        self.assertEqual(new["dispositions"][0]["run"], new_rid)
        self.assertEqual(new["timeline_validations"][0]["finding_id"], f"f:{new_rid}:1")
        self.assertEqual(new["fused_run_ids"], [new_rid])
        with open(self.store._graph_path(res["case_id"])) as f:
            g = json.load(f)
        self.assertEqual(g["case_id"], res["case_id"])
        self.assertEqual(g["run_ids"], [new_rid])
        self.assertEqual(g["entities"]["asset:endpoint:c1"]["evidence"][0]["run_id"],
                         new_rid)

    def test_importing_the_same_bundle_twice_makes_two_independent_cases(self):
        case_id, _ = self.make_case(runs=1)
        path, _ = self.export(case_id)
        a = cb.import_case_bundle(path)
        b = cb.import_case_bundle(path)
        self.assertNotEqual(a["case_id"], b["case_id"])
        self.assertNotEqual(a["name"], b["name"])
        am = self.ws.rows[a["case_id"]]["details"]["member_run_ids"]
        bm = self.ws.rows[b["case_id"]]["details"]["member_run_ids"]
        self.assertFalse(set(am) & set(bm), "the second import reused the first's runs")
        # and the first copy's payload is still its own
        for rid in am:
            self.assertTrue(os.path.exists(
                os.path.join(cb.DOWNLOAD_WRITE_DIR, rid, "raw_results.json")))

    def test_an_id_that_collides_with_a_destination_run_is_not_clobbered(self):
        """The failure the old importer shipped: same `<type>_<ms>` on two
        appliances, INSERT OR REPLACE, and a run silently stolen from its case."""
        case_id, members = self.make_case(runs=1)
        path, _ = self.export(case_id)
        victim_case = self.ws.create_automation_run("case", "Case — Other",
                                                    details={"name": "Other"})
        self.ws.rows[members[0]] = {"run_id": members[0],
                                    "automation_type": "velociraptor_collection",
                                    "name": "SOMEONE ELSE'S RUN", "details": {},
                                    "case_id": victim_case}
        cb.import_case_bundle(path)
        self.assertEqual(self.ws.rows[members[0]]["name"], "SOMEONE ELSE'S RUN")
        self.assertEqual(self.ws.rows[members[0]]["case_id"], victim_case)

    def test_a_longer_id_is_not_eaten_by_a_shorter_ones_prefix(self):
        ids = {"agentic_1755512400001": "agentic_9000000000001",
               "agentic_17555124000011": "agentic_9000000000002"}
        out = cb._remap("agentic_1755512400001 and agentic_17555124000011", ids)
        self.assertEqual(out, "agentic_9000000000001 and agentic_9000000000002")

    def test_remap_does_not_match_inside_a_longer_token(self):
        ids = {"memory_1755512400001": "memory_9000000000001"}
        self.assertEqual(cb._remap("xmemory_1755512400001x", ids),
                         "xmemory_1755512400001x")


# ── forward compatibility ────────────────────────────────────────────────────
class TestForwardCompat(BundleTestBase):
    def _rewrite_manifest(self, path, patch):
        out = path + ".patched"
        with zipfile.ZipFile(path) as src, zipfile.ZipFile(out, "w") as dst:
            for item in src.namelist():
                data = src.read(item)
                if item == cb.MANIFEST_NAME:
                    man = json.loads(data)
                    man.update(patch)
                    data = json.dumps(man).encode()
                dst.writestr(item, data)
        return out

    def test_a_bundle_from_a_newer_release_is_refused_with_an_explanation(self):
        case_id, _ = self.make_case(runs=0, payloads=False, baseline=False)
        path, _ = self.export(case_id)
        newer = self._rewrite_manifest(path, {"schema": cb.MAX_SUPPORTED_SCHEMA + 1})
        with self.assertRaises(cb.BundleError) as ctx:
            cb.import_case_bundle(newer)
        msg = str(ctx.exception)
        self.assertIn("newer Intact release", msg)
        self.assertIn("at least as new as the exporter", msg)

    def test_the_old_metadata_only_format_is_refused_with_a_way_forward(self):
        case_id, _ = self.make_case(runs=0, payloads=False, baseline=False)
        path, _ = self.export(case_id)
        old = self._rewrite_manifest(path, {"schema": 1})
        with self.assertRaises(cb.BundleError) as ctx:
            cb.import_case_bundle(old)
        self.assertIn("Re-export", str(ctx.exception))

    def test_a_foreign_zip_is_refused_by_name(self):
        p = os.path.join(self.tmp, "collector.zip")
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("results.json", "{}")
        with self.assertRaises(cb.BundleError) as ctx:
            cb.import_case_bundle(p)
        self.assertIn("offline-collector", str(ctx.exception))

    def test_unknown_manifest_keys_and_extra_members_are_ignored(self):
        """Additive change must not bump the schema — a future release adding a
        field has to stay importable by every release that promised to accept it."""
        case_id, _ = self.make_case(runs=1)
        path, _ = self.export(case_id)
        patched = self._rewrite_manifest(path, {"something_new": {"a": 1}})
        with zipfile.ZipFile(patched, "a") as zf:
            zf.writestr("notes/extra.txt", "a future release wrote this")
        res = cb.import_case_bundle(patched)
        self.assertEqual(res["runs_imported"], 1)

    def test_the_manifest_records_the_release_that_wrote_it(self):
        case_id, _ = self.make_case(runs=1)
        path, _ = self.export(case_id)
        with zipfile.ZipFile(path) as zf:
            man = json.loads(zf.read(cb.MANIFEST_NAME))
        self.assertEqual(man["kind"], cb.EXPORT_KIND)
        self.assertEqual(man["schema"], cb.BUNDLE_SCHEMA)
        self.assertIn("product_version", man)
        self.assertIn("exported_at", man)
        self.assertTrue(man["files"])


# ── integrity, and failing safely ────────────────────────────────────────────
class TestIntegrity(BundleTestBase):
    def _corrupt(self, path, member):
        out = path + ".corrupt"
        with zipfile.ZipFile(path) as src, zipfile.ZipFile(out, "w") as dst:
            for item in src.namelist():
                data = src.read(item)
                if item == member:
                    data = data.replace(b"evil.exe", b"good.exe")
                dst.writestr(item, data)
        return out

    def test_a_tampered_payload_is_caught_before_anything_is_written(self):
        case_id, members = self.make_case(runs=1)
        path, _ = self.export(case_id)
        bad = self._corrupt(path, f"payloads/{members[0]}/raw_results.json")
        before = set(self.ws.rows)
        with self.assertRaises(cb.BundleError) as ctx:
            cb.import_case_bundle(bad)
        self.assertIn("checksum mismatch", str(ctx.exception))
        self.assertEqual(set(self.ws.rows), before, "rows were written despite corruption")
        self.assertEqual(os.listdir(self.store.graph_dir), [f"{case_id}.json"])

    def test_a_manifest_listing_a_missing_file_is_caught(self):
        case_id, members = self.make_case(runs=1)
        path, _ = self.export(case_id)
        out = path + ".truncated"
        drop = f"payloads/{members[0]}/raw_results.json"
        with zipfile.ZipFile(path) as src, zipfile.ZipFile(out, "w") as dst:
            for item in src.namelist():
                if item != drop:
                    dst.writestr(item, src.read(item))
        with self.assertRaises(cb.BundleError) as ctx:
            cb.import_case_bundle(out)
        self.assertIn("incomplete", str(ctx.exception))

    def test_a_path_outside_the_layout_is_refused(self):
        case_id, _ = self.make_case(runs=0, payloads=False, baseline=False)
        path, _ = self.export(case_id)
        out = path + ".evil"
        with zipfile.ZipFile(path) as src, zipfile.ZipFile(out, "w") as dst:
            for item in src.namelist():
                data = src.read(item)
                if item == cb.MANIFEST_NAME:
                    man = json.loads(data)
                    man["files"].append({"path": "../../etc/cron.d/pwn",
                                         "sha256": "x", "bytes": 1})
                    data = json.dumps(man).encode()
                dst.writestr(item, data)
        with self.assertRaises(cb.BundleError) as ctx:
            cb.import_case_bundle(out)
        self.assertIn("unexpected file", str(ctx.exception))

    def test_a_failure_midway_leaves_nothing_behind(self):
        case_id, _ = self.make_case(runs=2)
        path, _ = self.export(case_id)
        before_rows = set(self.ws.rows)
        before_dirs = set(os.listdir(cb.DOWNLOAD_WRITE_DIR))

        real = cb.archive_guard.copy_bounded
        state = {"n": 0}

        def boom(src, dst, limit, **kw):
            state["n"] += 1
            if state["n"] > 1:
                raise OSError("disk fell over")
            return real(src, dst, limit, **kw)

        cb.archive_guard.copy_bounded = boom
        try:
            with self.assertRaises(OSError):
                cb.import_case_bundle(path)
        finally:
            cb.archive_guard.copy_bounded = real

        self.assertEqual(set(self.ws.rows), before_rows, "a half-imported case survived")
        self.assertEqual(set(os.listdir(cb.DOWNLOAD_WRITE_DIR)), before_dirs)
        self.assertEqual(os.listdir(self.store.graph_dir), [f"{case_id}.json"])


# ── export-side behaviour ────────────────────────────────────────────────────
class TestExportBehaviour(BundleTestBase):
    def test_a_purged_payload_warns_but_still_exports(self):
        """The Maintenance 'Report Downloads' purge deletes collected data. The
        case still has to be movable — it just cannot be re-fused afterwards, and
        that has to be said out loud rather than discovered after the move."""
        case_id, members = self.make_case(runs=2)
        shutil.rmtree(os.path.join(cb.DOWNLOAD_WRITE_DIR, members[0]))
        path, res = self.export(case_id)
        self.assertTrue(any("raw_results.json" in w for w in res["warnings"]))
        self.assertTrue(os.path.exists(path))
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
        self.assertIn(f"payloads/{members[1]}/raw_results.json", names)
        self.assertNotIn(f"payloads/{members[0]}/raw_results.json", names)

    def test_a_cloud_run_is_not_warned_about_a_file_it_never_has(self):
        """Measured on the live appliance: an aws_scan run was warned for a
        missing raw_results.json while its findings were in the bundle all along.
        Warnings operators learn to ignore are worse than no warnings."""
        case_id, _ = self.make_case(runs=1, aws=True)
        _, res = self.export(case_id)
        self.assertEqual(res["warnings"], [])

    def test_a_cloud_run_with_no_findings_anywhere_is_warned(self):
        case_id = self.ws.create_automation_run("case", "Case — C",
                                                details={"name": "C"})
        self.ws.create_automation_run("aws_scan", "AWS", details={}, case_id=case_id)
        _, res = self.export(case_id)
        self.assertTrue(any("cloud findings" in w for w in res["warnings"]))

    def test_a_timesketch_run_keeping_its_events_on_the_row_is_not_warned(self):
        """Its sketch does not exist on the destination; the distilled events on
        the row are what make it fuse there, and they travel with the row."""
        case_id = self.ws.create_automation_run("case", "Case — T",
                                                details={"name": "T"})
        self.ws.create_automation_run("timesketch", "TS", case_id=case_id,
                                      details={"timeline_events": [{"ts": "x"}]})
        _, res = self.export(case_id)
        self.assertEqual(res["warnings"], [])

    def test_a_timesketch_run_with_nothing_on_the_row_is_warned(self):
        case_id = self.ws.create_automation_run("case", "Case — T2",
                                                details={"name": "T2"})
        self.ws.create_automation_run("timesketch", "TS", details={"sketch_id": 3},
                                      case_id=case_id)
        _, res = self.export(case_id)
        self.assertTrue(any("Timesketch sketch" in w for w in res["warnings"]))

    def test_a_missing_memory_payload_says_the_yara_hits_are_unrecoverable(self):
        case_id = self.ws.create_automation_run("case", "Case — M",
                                                details={"name": "M"})
        self.ws.create_automation_run("memory", "Memory", details={}, case_id=case_id)
        _, res = self.export(case_id)
        self.assertTrue(any("YARA" in w for w in res["warnings"]),
                        f"no yara warning in {res['warnings']}")

    def test_export_warnings_reach_the_imported_cases_log(self):
        case_id, members = self.make_case(runs=2)
        shutil.rmtree(os.path.join(cb.DOWNLOAD_WRITE_DIR, members[0]))
        path, _ = self.export(case_id)
        res = cb.import_case_bundle(path)
        warned = [e for e in self.store.events
                  if e["case_id"] == res["case_id"] and e["status"] == "warning"]
        self.assertTrue(warned, "the destination was never told data was missing")

    def test_only_one_archive_is_kept_per_case(self):
        case_id, _ = self.make_case(runs=1)
        self.export(case_id)
        path2, _ = self.export(case_id)
        out_dir = os.path.join(cb.EXPORT_DIR, case_id)
        left = os.listdir(out_dir)
        self.assertEqual(left, [os.path.basename(path2)])
        self.assertFalse([f for f in left if f.endswith(".partial")])

    def test_exporting_an_unknown_case_is_a_clean_error(self):
        with self.assertRaises(cb.BundleError) as ctx:
            cb.plan_export("case_does_not_exist")
        self.assertIn("not found", str(ctx.exception))

    def test_the_bundle_is_streamed_not_built_in_memory(self):
        """A raw_results.json is ~547 MB; reading one whole is how the previous
        implementation would have died. Assert the file is never read at once."""
        case_id, _ = self.make_case(runs=1)
        real_open = open
        seen = []

        def watched(path, mode="r", *a, **kw):
            fh = real_open(path, mode, *a, **kw)
            if "raw_results.json" in str(path) and "b" in mode:
                orig = fh.read

                def read(n=-1):
                    seen.append(n)
                    return orig(n)
                fh.read = read
            return fh

        import builtins
        builtins.open = watched
        try:
            self.export(case_id)
        finally:
            builtins.open = real_open
        self.assertTrue(seen, "the payload was never read")
        self.assertTrue(all(n == cb._CHUNK for n in seen),
                        f"payload read in one gulp: {seen[:3]}")


# ── manifest reading as its own step (pre-flight for the UI) ─────────────────
class TestManifestReading(BundleTestBase):
    def test_read_manifest_describes_a_bundle_without_importing_it(self):
        case_id, members = self.make_case(runs=2)
        path, _ = self.export(case_id)
        before = set(self.ws.rows)
        man = cb.read_manifest(path)
        self.assertEqual(man["case_name"], "GOOGLE IR")
        self.assertEqual(len(man["member_run_ids"]), 2)
        self.assertEqual(len(man["baseline_run_ids"]), 1)
        self.assertTrue(man["has_graph"])
        self.assertEqual(set(self.ws.rows), before)

    def test_a_non_zip_is_refused(self):
        p = os.path.join(self.tmp, "notes.txt")
        with open(p, "w") as f:
            f.write("not a zip")
        with self.assertRaises(cb.BundleError):
            cb.read_manifest(p)


if __name__ == "__main__":
    unittest.main(verbosity=2)
