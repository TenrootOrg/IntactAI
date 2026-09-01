"""Does ranked search stay PRECISE at scale?

Ranked token-overlap search was measured on the 41-scenario corpus: 37 findings,
~2 results per query. That is a small graph. At 120 hosts / thousands of findings a
two-term query could match hundreds of titles, and the 15-result cap would then
return whatever severity-sorts highest rather than what is relevant -- turning a
recall win into a precision loss.

This plants a KNOWN needle finding into a large synthetic haystack and asks: does
the needle still come back, and at what rank?

  cd /app/scratch_eval && PYTHONPATH=/app:/app/scratch_eval/campaign \
      python3 campaign/eval_search_scale.py
"""
import json
import os
import sys

sys.path.insert(0, "/app")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # scratch_eval
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from services.fusion import store, investigate, schema  # noqa: E402
import synth_graph  # noqa: E402

OUT = "/tmp/eval_out/campaign"
os.makedirs(OUT, exist_ok=True)

# Distinctive needles, phrased by TITLE, queried the way an analyst would type it.
NEEDLES = [
    ("SIGMA: Volume Shadow Copy Deletion via Vssadmin on NEEDLE-01", "shadow copy deletion"),
    ("SIGMA: Security Eventlog Cleared on NEEDLE-02", "log clearing"),
    ("SIGMA: Rubeus Kerberos Ticket Request on NEEDLE-03", "kerberoasting rubeus"),
    ("SIGMA: Rclone Cloud Exfiltration on NEEDLE-04", "rclone exfiltration"),
    ("SIGMA: Mimikatz LSASS Credential Dumping on NEEDLE-05", "lsass credential dumping"),
]


class _Patch:
    def __init__(self, obj, **a):
        self.obj, self.a, self.s = obj, a, {}

    def __enter__(self):
        for k, v in self.a.items():
            self.s[k] = getattr(self.obj, k, None)
            setattr(self.obj, k, v)
        return self

    def __exit__(self, *_):
        for k, v in self.s.items():
            setattr(self.obj, k, v)


def run_scale(hosts, findings):
    g, _d = synth_graph.synth(hosts, 90, findings)
    # plant the needles as ordinary findings on their own hosts
    for i, (title, _q) in enumerate(NEEDLES):
        hid = "asset:needle:%d" % i
        g.entities[hid] = schema.Entity(id=hid, type="asset",
                                        label="NEEDLE-%02d" % (i + 1))
        g.findings.append(schema.Finding(
            id="needle:%d" % i, title=title, severity="high", confidence="medium",
            summary="", asset_ids=[hid], ts="2026-06-01T00:00:00Z"))
    rows = []
    with _Patch(store, load_graph=lambda c: g):
        for i, (title, q) in enumerate(NEEDLES):
            res = investigate._tool(g.case_id, "search", {"query": q})
            rank = next((k for k, r in enumerate(res) if r["id"] == "needle:%d" % i), None)
            rows.append({"hosts": hosts, "findings": len(g.findings), "query": q,
                         "n_results": len(res), "rank": rank,
                         "found": rank is not None, "top1": rank == 0,
                         "top5": rank is not None and rank < 5,
                         "host_ok": bool(res and rank is not None
                                         and "NEEDLE-%02d" % (i + 1) in
                                         " ".join(res[rank].get("hosts") or []))})
    return rows


def main():
    all_rows = []
    for hosts, findings in [(10, 60), (40, 600), (120, 3000)]:
        all_rows += run_scale(hosts, findings)

    lines = ["# Ranked search precision at scale", "",
             "A known needle finding is planted in a synthetic haystack and queried "
             "with analyst phrasing. Recall was measured on a 37-finding graph; this "
             "asks whether the ranking still isolates the needle when the graph is "
             "two orders of magnitude larger.", "",
             "| Hosts | Findings | Query | Results | Rank | Top-1 | Top-5 | Host shown |",
             "|---|---|---|---|---|:--:|:--:|:--:|"]
    for r in all_rows:
        lines.append("| %d | %d | %s | %d | %s | %s | %s | %s |" % (
            r["hosts"], r["findings"], r["query"], r["n_results"],
            "—" if r["rank"] is None else r["rank"] + 1,
            "✅" if r["top1"] else "❌", "✅" if r["top5"] else "❌",
            "✅" if r["host_ok"] else "❌"))

    by_scale = {}
    for r in all_rows:
        by_scale.setdefault(r["findings"], []).append(r)
    lines += ["", "## Summary", "",
              "| Findings in graph | Top-1 | Top-5 | Mean results/query |",
              "|---|---|---|---|"]
    for n in sorted(by_scale):
        rs = by_scale[n]
        lines.append("| %d | %d/%d | %d/%d | %.1f |" % (
            n, sum(r["top1"] for r in rs), len(rs),
            sum(r["top5"] for r in rs), len(rs),
            sum(r["n_results"] for r in rs) / len(rs)))

    md = "\n".join(lines) + "\n"
    open("%s/search_scale.md" % OUT, "w").write(md)
    json.dump(all_rows, open("%s/search_scale.json" % OUT, "w"), indent=2, default=str)
    print(md)
    t1 = sum(r["top1"] for r in all_rows)
    t5 = sum(r["top5"] for r in all_rows)
    print("Search at scale: top1 %d/%d, top5 %d/%d" % (t1, len(all_rows), t5, len(all_rows)))


if __name__ == "__main__":
    main()
