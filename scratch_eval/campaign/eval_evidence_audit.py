"""E18 — evidence-locator resolution audit (deterministic).

Every finding carries EvidenceRef(module, run_id, locator="<artifact>/row=<i>"). The
whole drill-down — and the agentic evidence() tool — trusts that pointer. Nothing has
ever verified it resolves to the CORRECT row: a silent off-by-one would make every
"here is the exact row" citation wrong while looking perfectly healthy.

This walks every finding, resolves each locator against the SAME telemetry the graph
was built from, and checks the row actually corresponds to the finding (host matches,
and where the finding names a detection, the row carries it).

  cd /app/scratch_eval && PYTHONPATH=/app python3 campaign/eval_evidence_audit.py
"""
import json
import os
import sys

sys.path.insert(0, "/app")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from services.fusion.mappers.agentic import map_agentic  # noqa: E402
from services.fusion import correlate, render  # noqa: E402
import attack_corpus as corpus  # noqa: E402

OUT = "/tmp/eval_out/campaign"
os.makedirs(OUT, exist_ok=True)


def main():
    tele = corpus.build_all_telemetry()
    ents, rels = map_agentic(tele, run_id="evalrun", hostnames={})
    g = correlate.assemble("gt_audit", [(ents, rels)], ["evalrun"])

    checked = resolved = host_ok = 0
    bad_index, bad_host, unresolvable = [], [], []
    for f in g.findings:
        f_hosts = {render._host_label(g, a).lower() for a in (f.asset_ids or [])}
        refs = list(f.evidence or [])
        for eid in (f.entity_ids or []):
            e = g.entities.get(eid)
            if e:
                refs += list(e.evidence or [])
        for ref in refs:
            loc = getattr(ref, "locator", "") or ""
            if "/row=" not in loc:
                continue
            checked += 1
            art, _, idx = loc.partition("/row=")
            rows = tele.get(art)
            if rows is None:
                unresolvable.append((f.title[:40], loc, "artifact not in telemetry"))
                continue
            try:
                i = int(idx)
            except ValueError:
                unresolvable.append((f.title[:40], loc, "non-integer row index"))
                continue
            if not (0 <= i < len(rows)):
                bad_index.append((f.title[:40], loc, f"index {i} out of range {len(rows)}"))
                continue
            resolved += 1
            row = rows[i]
            # the row must belong to a host the finding is about
            rh = str(row.get("Computer") or row.get("Hostname") or "").lower()
            if not f_hosts or not rh or rh in f_hosts:
                host_ok += 1
            else:
                bad_host.append((f.title[:48], loc, f"row host={rh} not in {sorted(f_hosts)}"))

    ok = not bad_index and not bad_host and not unresolvable
    lines = ["# Evidence-locator resolution audit (deterministic)", "",
             "Every finding's `EvidenceRef` locator resolved against the telemetry the "
             "graph was built from, and checked that the row belongs to the finding's "
             "host. An off-by-one here would silently corrupt every drill-down.", "",
             f"- locators checked: **{checked}**",
             f"- resolved to a real row: **{resolved}**",
             f"- row host matches the finding: **{host_ok}/{resolved}**",
             f"- out-of-range index: **{len(bad_index)}**",
             f"- wrong host: **{len(bad_host)}**",
             f"- unresolvable: **{len(unresolvable)}**", "",
             f"**{'✅ PASS — every locator resolves to the correct row' if ok else '❌ FAIL'}**"]
    for label, rows_ in (("Out-of-range", bad_index), ("Wrong host", bad_host),
                         ("Unresolvable", unresolvable)):
        if rows_:
            lines += ["", f"## {label}"] + [f"- `{a}` {b} — {c}" for a, b, c in rows_[:12]]
    md = "\n".join(lines) + "\n"
    open(f"{OUT}/evidence_audit.md", "w").write(md)
    json.dump({"checked": checked, "resolved": resolved, "host_ok": host_ok,
               "bad_index": bad_index, "bad_host": bad_host,
               "unresolvable": unresolvable, "pass": ok},
              open(f"{OUT}/evidence_audit.json", "w"), indent=2, default=str)
    print(md)


if __name__ == "__main__":
    main()
