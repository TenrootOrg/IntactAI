"""One Timeline row = one detection until it goes quiet — across hosts.

Found on a real case (jev_test, 9 hosts, 183k Hayabusa rows):
  * a rule's whole history was ONE row placed at its first hit — rows spanned up
    to 341 days, so an attacker returning months later was invisible in time;
  * the same rule on different hosts was one row per host, and their ranges
    overlapped (10:30-11:00 beside 10:35-10:45): 61 overlapping pairs;
  * a folded SIGMA row said "1 occurrence" and "last seen" at its FIRST hit
    (26 of 55 rows), so a Known/False-positive verdict could never re-open;
  * a scope hid rows that started before it but kept firing inside it.

These drive the REAL mapper and the REAL fusion pass on raw Hayabusa rows.
"""
import os
import sys
import types
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import correlate, keys, render, schema  # noqa: E402
from services.fusion.mappers.agentic import map_agentic  # noqa: E402


def _row(host, ts, title="Suspicious Encoded PowerShell Command Line", level="high", rec=1):
    return {"Timestamp": ts, "Title": title, "Level": level, "Computer": host,
            "Channel": "Microsoft-Windows-PowerShell/Operational", "EID": 4104,
            "RecordID": rec, "Details": "Cmdline: powershell -enc AAAA",
            "_hostname": host, "_client_id": "C." + host}


def _fuse(*runs, window=None):
    contribs, rids = [], []
    for i, rows in enumerate(runs):
        rid = f"r{i}"
        ents, rels = map_agentic({"Windows.Hayabusa.Rules": rows}, run_id=rid)
        contribs.append((ents, rels))
        rids.append(rid)
    return correlate.assemble("c", contribs, rids, window=window)


def _rows_of(g, title="Suspicious Encoded PowerShell Command Line"):
    return sorted((f for f in g.findings if title in f.title), key=lambda f: f.ts)


class SplitEpisodes(unittest.TestCase):
    def test_gap_ranges_and_undated(self):
        ts = ["2026-06-01T10:00:00Z", "2026-06-01T12:00:00Z", "2026-06-01T20:00:00Z", None]
        eps = keys.split_episodes(ts, lambda t: t)
        self.assertEqual(eps, [["2026-06-01T10:00:00Z", "2026-06-01T12:00:00Z", None],
                               ["2026-06-01T20:00:00Z"]])
        # a range that overlaps the next start keeps them together, even across a gap
        rng = [("2026-06-01T10:00:00Z", "2026-06-01T18:00:00Z"), ("2026-06-01T17:00:00Z", None)]
        self.assertEqual(len(keys.split_episodes(rng, lambda r: r[0], end_of=lambda r: r[1])), 1)
        self.assertEqual(keys.split_episodes([], lambda t: t), [])


class OneHost(unittest.TestCase):
    def test_a_rule_that_returns_months_later_is_two_rows(self):
        g = _fuse([_row("HOSTA", "2026-01-10T10:00:00Z", rec=1),
                   _row("HOSTA", "2026-01-10T10:30:00Z", rec=2),
                   _row("HOSTA", "2026-06-02T09:00:00Z", rec=3)])
        rows = _rows_of(g)
        self.assertEqual(len(rows), 2)
        self.assertEqual([r.occ_count for r in rows], [2, 1])
        self.assertTrue(str(rows[0].occ_latest).startswith("2026-01-10T10:30"))   # real last hit
        self.assertTrue(str(rows[1].ts).startswith("2026-06-02"))

    def test_the_first_episode_keeps_the_old_id_so_verdicts_stay(self):
        g = _fuse([_row("HOSTA", "2026-01-10T10:00:00Z", rec=1),
                   _row("HOSTA", "2026-06-02T09:00:00Z", rec=2)])
        old_id = correlate._fid("sigma", "asset:endpoint:C.HOSTA:Suspicious Encoded PowerShell Command Line")
        rows = _rows_of(g)
        if rows[0].asset_ids != ["asset:endpoint:C.HOSTA"]:
            self.skipTest(f"asset id shape changed: {rows[0].asset_ids}")
        self.assertEqual(rows[0].id, old_id)
        self.assertNotEqual(rows[1].id, old_id)

    def test_count_and_last_seen_are_the_real_ones(self):
        rows = _rows_of(_fuse([_row("HOSTA", f"2026-01-10T10:{m:02d}:00Z", rec=m) for m in range(0, 50, 5)]))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].occ_count, 10)
        self.assertTrue(str(rows[0].occ_latest).startswith("2026-01-10T10:45"))


class AcrossHosts(unittest.TestCase):
    """The same detection on several hosts close together is GROUPED, never merged:
    each host keeps its own row (and its own verdict), and the rows share a label."""

    def test_same_rule_close_together_on_two_hosts_is_one_group_of_two_rows(self):
        g = _fuse([_row("HOSTA", "2026-06-01T10:30:00Z", rec=1), _row("HOSTA", "2026-06-01T11:00:00Z", rec=2)],
                  [_row("HOSTB", "2026-06-01T10:35:00Z", rec=3), _row("HOSTB", "2026-06-01T10:45:00Z", rec=4)])
        rows = _rows_of(g)
        self.assertEqual(len(rows), 2)
        self.assertEqual({len(r.asset_ids) for r in rows}, {1})
        self.assertEqual(rows[0].group["id"], rows[1].group["id"])
        self.assertEqual((rows[0].group["hosts"], rows[0].group["link"]), (2, "time only"))
        self.assertEqual(sorted(r.occ_count for r in rows), [2, 2])

    def test_far_apart_on_two_hosts_is_not_a_group(self):
        g = _fuse([_row("HOSTA", "2026-06-01T10:00:00Z", rec=1)],
                  [_row("HOSTB", "2026-06-03T10:00:00Z", rec=2)])
        self.assertEqual([r.group for r in _rows_of(g)], [None, None])

    def test_no_chaining_through_a_host_in_between(self):
        # 10:00, 13:30, 17:00 — each within 4 h of the previous, but 17:00 is 7 h
        # after the first: two groups, not one bridged by the middle host
        g = _fuse([_row("HOSTA", "2026-06-01T10:00:00Z", rec=1)],
                  [_row("HOSTB", "2026-06-01T13:30:00Z", rec=2)],
                  [_row("HOSTC", "2026-06-01T17:00:00Z", rec=3)])
        rows = _rows_of(g)
        self.assertEqual(rows[0].group["id"], rows[1].group["id"])
        self.assertIsNone(rows[2].group)

    def test_adding_a_host_changes_no_existing_row(self):
        a = [_row("HOSTA", "2026-06-01T10:30:00Z", rec=1)]
        b = [_row("HOSTB", "2026-06-01T10:40:00Z", rec=2)]
        c = [_row("HOSTC", "2026-06-01T10:20:00Z", rec=3)]          # earlier than both
        before = {(r.asset_ids[0], r.id, r.occ_count, r.watermark()) for r in _rows_of(_fuse(a, b))}
        after = _rows_of(_fuse(a, b, c))
        self.assertTrue(before <= {(r.asset_ids[0], r.id, r.occ_count, r.watermark()) for r in after})
        self.assertEqual(len(after), 3)

    def test_a_shared_account_is_named_as_the_link(self):
        ra = _row("HOSTA", "2026-06-01T10:30:00Z", rec=1)
        rb = _row("HOSTB", "2026-06-01T10:40:00Z", rec=2)
        for r in (ra, rb):
            r["Details"] = "User: CORP\\kobia ¦ Cmdline: powershell -enc AAAA"
        link = _rows_of(_fuse([ra], [rb]))[0].group["link"]
        self.assertTrue(link.startswith("same account"), link)

    def test_one_hosts_rows_of_a_detection_never_overlap(self):
        import random
        rnd = random.Random(7)
        runs = []
        for h in ("HOSTA", "HOSTB", "HOSTC"):
            runs.append([_row(h, f"2026-06-{rnd.randint(1, 5):02d}T{rnd.randint(0, 23):02d}:"
                                 f"{rnd.randint(0, 59):02d}:00Z", rec=rnd.randint(1, 10**6))
                         for _ in range(40)])
        g = _fuse(*runs)
        # The range comes from the rows' EVENTS (their real last hits), not from
        # occ_latest: the old code set occ_latest to the first hit, which made every
        # row look like a single moment and hid its own overlaps from this check.
        def span(r):
            evs = [g.entities[i] for i in r.entity_ids if i in g.entities]
            return (min(keys.to_utc_dt(e.first_seen) for e in evs),
                    max(keys.to_utc_dt(e.last_seen or e.first_seen) for e in evs))
        by_host: dict = {}
        for r in _rows_of(g):
            by_host.setdefault(r.asset_ids[0], []).append(span(r))
        for spans in by_host.values():
            spans.sort()
            for (a0, a1), (b0, b1) in zip(spans, spans[1:]):
                self.assertLess(a1, b0, "two rows of one detection on one host overlap")


class VerdictsAndAliases(unittest.TestCase):
    """"+N related" (one Windows event, several rules) still folds rows into one,
    and a verdict given on an absorbed row still applies to the folded row."""

    def test_aliases_survive_save_and_load(self):
        from services.fusion.schema import Finding
        f = Finding(id="new", title="t", severity="high", confidence="high", summary="",
                    aliases=["old-a", "old-b"], group={"id": "g1", "hosts": 2})
        back = Finding.from_dict(f.to_dict())
        self.assertEqual((back.ids(), back.group), (["new", "old-a", "old-b"], {"id": "g1", "hosts": 2}))

    def test_a_disposition_on_an_alias_applies(self):
        from services.fusion.schema import Finding
        g = types.SimpleNamespace(findings=[Finding(id="new", title="t on H", severity="high",
                                                    confidence="high", summary="s",
                                                    aliases=["old-b"])])
        correlate._apply_dispositions(g, [{"target": "old-b", "verdict": "benign",
                                           "attribution": "operator"}])
        self.assertEqual(g.findings[0].kind, "dispositioned")


class FileRows(unittest.TestCase):
    """Found live: "Known tool on disk: AdFind.exe" was one row per host with
    overlapping ranges, and one host's row spanned 341 days of separate drops."""

    def _fuse(self, *drops):
        ents = []
        for i, (host, ts) in enumerate(drops):
            a = f"asset:{host}"
            if a not in {e.id for e in ents}:
                ents.append(schema.Entity(id=a, type="asset", label=host))
            ents.append(schema.Entity(
                id=f"ev:adfind:{i}", type="event", label="AdFind.exe", severity="high",
                first_seen=ts, flags=["detection", "masquerading"],
                attrs={"_assets": [a], "title": "Renamed binary: AdFind.exe",
                       "original_name": "AdFind.exe", "name": "AdFind.exe",
                       "path": rf"C:\Tools\{i}\AdFind.exe", "full_hash": "a" * 64},
                evidence=[schema.EvidenceRef("velociraptor", "r1",
                                             f"DetectRaptor.Windows.Detection.BinaryRename/row={i}")]))
        g = correlate.assemble("c", [(ents, [])], ["r1"], min_severity="medium")
        return sorted((f for f in g.findings if "AdFind" in f.title), key=lambda f: f.ts)

    def test_same_tool_on_two_hosts_close_together_is_one_group(self):
        rows = self._fuse(("ALClient01", "2025-05-27T11:17:01Z"), ("ALClient09", "2025-05-27T12:00:00Z"))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0].group["id"], rows[1].group["id"])
        self.assertTrue(rows[0].group["link"].startswith("same hash"))

    def test_two_different_files_with_one_name_are_told_apart(self):
        ents = [schema.Entity(id="asset:H", type="asset", label="ALClient06")]
        for i, h in enumerate(("3fa1c2d0" + "0" * 56, "9b77e210" + "0" * 56)):
            ents.append(schema.Entity(
                id=f"ev:pv:{i}", type="event", label="peview.exe", severity="high",
                first_seen="2026-01-26T11:51:42Z", flags=["detection", "masquerading"],
                attrs={"_assets": ["asset:H"], "title": "Renamed binary: peview.exe",
                       "original_name": "peview.exe", "name": "peview.exe", "full_hash": h},
                evidence=[schema.EvidenceRef("velociraptor", "r1",
                                             f"DetectRaptor.Windows.Detection.BinaryRename/row={i}")]))
        g = correlate.assemble("c", [(ents, [])], ["r1"], min_severity="medium")
        titles = sorted(f.title for f in g.findings if "peview" in f.title)
        self.assertEqual(titles, ["Known tool on disk: peview.exe (sha256 3fa1c2d0…) on ALClient06",
                                  "Known tool on disk: peview.exe (sha256 9b77e210…) on ALClient06"])

    def test_separate_drops_months_apart_are_separate_rows(self):
        rows = self._fuse(("ALClient01", "2025-05-27T11:17:01Z"), ("ALClient01", "2026-05-03T09:00:00Z"))
        self.assertEqual(len(rows), 2)


class Recurring(unittest.TestCase):
    """Found live: a scheduled service firing twice at ~10:52 every day became one
    row per day (dozens), each "Jev: likely True Positive 92%"."""

    def _days(self, days, hour=10, minute=52, hits=2, host="HOSTA", extra=()):
        rows, rec = [], 0
        for d in days:
            for k in range(hits):
                rec += 1
                rows.append(_row(host, f"2026-04-{d:02d}T{hour:02d}:{minute + k * 5:02d}:00Z", rec=rec))
        for ts, n in extra:
            for k in range(n):
                rec += 1
                rows.append(_row(host, ts.replace("MM", f"{k % 60:02d}"), rec=rec))
        return _rows_of(_fuse(rows))

    def test_a_daily_routine_is_one_row(self):
        rows = self._days(range(1, 11))
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertIn("(recurring daily ~10:52)", r.title)
        self.assertEqual((r.recurring["days"], r.occ_count, len(r.aliases)), (10, 20, 9))

    def test_a_break_from_the_routine_stays_its_own_row(self):
        # days 1-7 and 9-10 routine; day 8 fires 40 times at the routine time (inside
        # the run, so only the hit-count rule can take it out); an extra 03:00 run on day 4
        rows = self._days([1, 2, 3, 4, 5, 6, 7, 9, 10],
                          extra=[("2026-04-04T03:MM:00Z", 1), ("2026-04-08T10:MM:00Z", 40)])
        recurring = [r for r in rows if r.recurring]
        other = [r for r in rows if not r.recurring]
        self.assertEqual(len(recurring), 1)
        self.assertEqual(recurring[0].recurring["days"], 9)                 # the heavy day is not in it
        self.assertEqual(sorted(r.occ_count for r in other), [1, 40])

    def test_too_few_days_is_not_a_routine(self):
        self.assertTrue(all(not r.recurring for r in self._days([1, 2])))

    def test_the_next_routine_day_keeps_a_verdict_a_changed_routine_reopens_it(self):
        wm10 = self._days(range(1, 11))[0].watermark()
        wm11 = self._days(range(1, 12))[0].watermark()
        self.assertTrue(wm10.startswith("R|10:52|"))
        self.assertFalse(correlate._wm_new_activity(wm10, wm11))            # one more normal day
        heavier = self._days(range(1, 11), hits=9)[0].watermark()
        self.assertTrue(correlate._wm_new_activity(wm10, heavier))          # routine changed
        self.assertTrue(correlate._wm_new_activity("2|2026-04-01T10:57:00Z", wm10))  # pre-routine verdict

    def test_the_first_days_id_is_kept_so_its_verdict_stays(self):
        first_day = _rows_of(_fuse([_row("HOSTA", "2026-04-01T10:52:00Z", rec=1)]))[0].id
        self.assertEqual(self._days(range(1, 11))[0].id, first_day)


class Scope(unittest.TestCase):
    def test_a_row_active_inside_a_scope_is_in_it(self):
        g = _fuse([_row("HOSTA", f"2026-05-31T{h:02d}:00:00Z", rec=h) for h in range(20, 24)]
                  + [_row("HOSTA", f"2026-06-01T{h:02d}:00:00Z", rec=100 + h) for h in range(0, 3)])
        win = {"start": "2026-06-01T00:30:00Z", "end": "2026-06-02T00:00:00Z"}
        row = _rows_of(g)[0]
        self.assertTrue(str(row.ts).startswith("2026-05-31"))           # started before the scope
        self.assertTrue(correlate.finding_in_window(row, win))
        self.assertIn(row.id, {r["finding_id"] for r in render.timeline(g, window=win)})
        self.assertFalse(correlate.finding_in_window(row, {"start": "2026-06-05T00:00:00Z",
                                                            "end": "2026-06-06T00:00:00Z"}))

    def test_timeline_row_shows_range_and_hits(self):
        g = _fuse([_row("HOSTA", "2026-01-10T10:00:00Z", rec=1), _row("HOSTA", "2026-01-10T10:40:00Z", rec=2)])
        r = [x for x in render.timeline(g) if "Encoded PowerShell" in x["title"]][0]
        self.assertEqual((r["hits"], r["last"]), (2, "2026-01-10T10:40:00Z"))


class RowDisplay(unittest.TestCase):
    """The real _tlUntil from cases.html, run in node."""

    def test_range_is_shown_compactly(self):
        import json, re, shutil, subprocess, tempfile
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "modules/nginx/html/cases.html"), encoding="utf-8") as fh:
            src = fh.read()
        fn = re.search(r"function _tlUntil\(r\)\{.*?\n\}", src, re.S)
        self.assertTrue(fn, "_tlUntil missing from cases.html")
        js = ("const esc=s=>String(s);\n" + fn.group(0) + """
console.log(JSON.stringify([
  _tlUntil({ts:'2026-06-01T10:30:00Z', last:'2026-06-01T11:00:00Z'}),
  _tlUntil({ts:'2026-06-01T10:30:00Z', last:'2026-06-03T09:00:00Z'}),
  _tlUntil({ts:'2026-06-01T10:30:00Z', last:'2026-06-01T10:30:00Z'}),
  _tlUntil({ts:'2026-06-01T10:30:00Z'})]));""")
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as t:
            t.write(js)
        try:
            out = json.loads(subprocess.run([node, t.name], capture_output=True, text=True,
                                            check=True).stdout)
        finally:
            os.unlink(t.name)
        self.assertIn("→ 11:00:00Z", out[0])                 # same day: time only
        self.assertIn("→ 2026-06-03T09:00:00Z", out[1])      # another day: full date
        self.assertEqual(out[2:], ["", ""])                  # a single moment: nothing


if __name__ == "__main__":
    unittest.main()
