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
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import correlate, keys, render  # noqa: E402
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
    def test_same_rule_close_together_on_two_hosts_is_one_row(self):
        g = _fuse([_row("HOSTA", "2026-06-01T10:30:00Z", rec=1), _row("HOSTA", "2026-06-01T11:00:00Z", rec=2)],
                  [_row("HOSTB", "2026-06-01T10:35:00Z", rec=3), _row("HOSTB", "2026-06-01T10:45:00Z", rec=4)])
        rows = _rows_of(g)
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(rows[0].asset_ids), 2)
        self.assertEqual(rows[0].occ_count, 4)
        self.assertIn("on 2 hosts", rows[0].title)

    def test_far_apart_on_two_hosts_stays_two_rows(self):
        g = _fuse([_row("HOSTA", "2026-06-01T10:00:00Z", rec=1)],
                  [_row("HOSTB", "2026-06-03T10:00:00Z", rec=2)])
        self.assertEqual(len(_rows_of(g)), 2)

    def test_rows_of_one_detection_never_overlap(self):
        import random
        rnd = random.Random(7)
        runs = []
        for h in ("HOSTA", "HOSTB", "HOSTC"):
            runs.append([_row(h, f"2026-06-{rnd.randint(1, 5):02d}T{rnd.randint(0, 23):02d}:"
                                 f"{rnd.randint(0, 59):02d}:00Z", rec=rnd.randint(1, 10**6))
                         for _ in range(40)])
        g = _fuse(*runs)
        rows = _rows_of(g)
        # The range comes from the rows' EVENTS (their real last hits), not from
        # occ_latest: the old code set occ_latest to the first hit, which made every
        # row look like a single moment and hid its own overlaps from this check.
        def span(r):
            evs = [g.entities[i] for i in r.entity_ids if i in g.entities]
            return (min(keys.to_utc_dt(e.first_seen) for e in evs),
                    max(keys.to_utc_dt(e.last_seen or e.first_seen) for e in evs))
        spans = sorted(span(r) for r in rows)
        for (a0, a1), (b0, b1) in zip(spans, spans[1:]):
            self.assertLess(a1, b0, "two rows of the same detection overlap in time")


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
