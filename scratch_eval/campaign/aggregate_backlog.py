"""Track F — merge every track's findings into one ranked backlog: the answer to
"what do we need to improve or implement". Reads each track's *.json in the
campaign output dir, ranks by severity, splits fix-vs-implement, and appends the
quantified rates from the matrix run when present.

  cd /app/scratch_eval && PYTHONPATH=/app python3 campaign/aggregate_backlog.py
"""
import glob
import json
import os

OUT = "/tmp/eval_out/campaign"
SEV = {"high": 0, "medium": 1, "low": 2, "info": 3}

# curated proposed action + fix/implement class per known finding id
ACTION = {
    "A1": ("fix", "Guard the loop: never accept a turn-1 {final} with 0 tool calls — "
                   "re-prompt 'call a tool first' (bounded retries), or force one list_findings."),
    "A2": ("fix", "Wrap _tool dispatch in try/except; return {'error':...} to the model "
                   "instead of letting a model-controlled arg raise a 500."),
    "A3": ("fix", "Catch LLMUnavailable in investigate() (or the route) and return the "
                   "typed operator message the report/chat paths already use."),
    "A7b": ("fix", "On the forced-final path, if the reply still isn't {final}, return a "
                    "clear 'insufficient evidence' message, never the raw tool-call blob."),
    "F2": ("fix", "Make schema._wider compare via keys.to_utc_dt instants (like in_window), "
                  "not lexicographic strings — mixed Z/fractional/epoch widen wrong."),
    "F2b": ("fix", "Same for correlate._wm_new_activity's watermark time half — compare "
                   "instants so a fractional-second-newer occurrence re-opens correctly."),
    "F3": ("implement", "Either wire TRIGGER_IDENTITY to re-fuse on an identity decision "
                        "(immediate effect) or delete the dead constant + document the "
                        "deferred-apply semantics."),
    "A5": ("implement", "Add bounded self-consistency / retry on the loop (Codex has no "
                        "temperature knob); the min-step guard (A1) also cuts variance impact."),
    "A8": ("implement", "Extend the mask sweep to raw-row values before they reach the model "
                        "(or redact unknown identifier-shaped tokens in tool output)."),
    "A6": ("implement", "Pass a role hint (DC/CA/MECM) through the masked tool output so "
                        "the model keeps tier-zero priority when hostnames are pseudonymized."),
}


def load_all():
    out = []
    for p in sorted(glob.glob(f"{OUT}/*.json")):
        try:
            d = json.load(open(p))
        except Exception:
            continue
        for f in d.get("findings", []):
            if f.get("status") == "FINDING":
                f["_track"] = d.get("track", os.path.basename(p))
                out.append(f)
    return out


def matrix_rates():
    p = f"{OUT}/matrix_results.json"
    if not os.path.exists(p):
        return None
    R = json.load(open(p))
    n = giveup = fab = 0
    for k, r in R.items():
        if r.get("error"):
            continue
        n += 1
        giveup += 1 if r.get("giveup") else 0
        fab += 1 if r.get("fabricated") else 0
    return {"n": n, "giveup": giveup, "fab": fab}


def main():
    findings = load_all()
    # de-dup by id, keep highest severity
    by_id = {}
    for f in findings:
        cur = by_id.get(f["id"])
        if cur is None or SEV.get(f["severity"], 9) < SEV.get(cur["severity"], 9):
            by_id[f["id"]] = f
    findings = sorted(by_id.values(), key=lambda x: (SEV.get(x["severity"], 9), x["id"]))
    mr = matrix_rates()

    rows = ["# Campaign BACKLOG — what to fix / implement", "",
            "Ranked findings from the fusion + agentic test campaign "
            "(Tracks A/B/C, deterministic + at-scale). Each links a repro; "
            "action is the proposed fix or feature.", ""]
    if mr and mr["n"]:
        rows += [f"**Quantified at scale (Track B, {mr['n']} model runs):** "
                 f"turn-1 give-up (A1) **{round(100*mr['giveup']/mr['n'],1)}%**, "
                 f"fabricated-host **{round(100*mr['fab']/mr['n'],1)}%**.", ""]
    fixes = [f for f in findings if ACTION.get(f["id"], ("fix",))[0] == "fix"]
    impls = [f for f in findings if ACTION.get(f["id"], ("fix",))[0] != "fix"]

    def block(title, items):
        r = [f"## {title}", "", "| Sev | ID | Track | Finding | Proposed action |",
             "|---|---|---|---|---|"]
        for f in items:
            act = ACTION.get(f["id"], ("fix", "—"))[1]
            r.append(f"| {f['severity']} | {f['id']} | {f.get('_track','')} | "
                     f"{f['title']} | {act} |")
        r.append("")
        return r

    rows += block("FIX (defects)", fixes)
    rows += block("IMPLEMENT (capability gaps)", impls)
    rows += ["## Repros", ""]
    for f in findings:
        rows.append(f"- **{f['id']}** ({f['severity']}): {f.get('repro','')}  \n  {f.get('detail','')}")
    md = "\n".join(rows) + "\n"
    open(f"{OUT}/BACKLOG.md", "w").write(md)
    print(md)
    print(f"wrote {OUT}/BACKLOG.md — {len(fixes)} fixes, {len(impls)} implements")


if __name__ == "__main__":
    main()
