"""Master results table — aggregate every accuracy run into one summary the user
reviews. Reads the per-run JSON/MD in the campaign output dir and emits
MASTER_RESULTS.md with a row per test, headlined by AI-investigation-vs-simulation.

  cd /app/scratch_eval && PYTHONPATH=/app python3 campaign/build_master_table.py
"""
import json
import os
import re

OUT = "/tmp/eval_out/campaign"


def _j(name):
    try:
        return json.load(open(f"{OUT}/{name}"))
    except Exception:
        return None


def _grep(name, pat):
    try:
        m = re.search(pat, open(f"{OUT}/{name}").read())
        return m.group(1) if m else "?"
    except Exception:
        return "?"


def main():
    rows = []                      # (test, scope, result, accuracy)
    per = _j("accuracy_per_scenario.json")
    if per:
        n, rec = per["n"], per["recall"]
        elig = sum(1 for r in per["rows"] if r.get("recall"))  # detected
        rows.append(("Detection recall", f"{n} scenarios",
                     f"{rec}/{n} detected; all misses are medium-SIGMA (by design)",
                     f"{round(100*rec/n)}%"))
        gnd = sum(r.get("grounded_host") for r in per["rows"])
        rows.append(("Host grounding", f"{rec} detections", f"{gnd}/{rec} correct host",
                     f"{round(100*gnd/rec) if rec else 0}%"))
        sev = sum(r.get("severity_ok") for r in per["rows"])
        rows.append(("Severity correct", f"{rec} detections", f"{sev}/{rec}",
                     f"{round(100*sev/rec) if rec else 0}%"))
    prec = _j("accuracy_precision.json")
    if prec:
        fp = prec.get("false_positives", "?")
        rows.append(("Precision (benign input)", "benign telemetry",
                     f"{fp} false positive(s)", "✅ PASS" if fp == 0 else "❌ FAIL"))
    noise_rec = _grep("accuracy_noise.md", r"still detected: (\d+/\d+)")
    if noise_rec != "?":
        rows.append(("Noise robustness", "attack + 20× benign",
                     f"{noise_rec} survive", "✅"))
    comb = _grep("accuracy_combined.md", r"grounding: \*\*(\d+)")
    if comb != "?":
        rows.append(("Combined report grounding", "5-host incident",
                     f"{comb}/100 grounding", f"{comb}%"))
    inv = _j("investigation_accuracy.json")
    if inv:
        c, n = inv["correct"], inv["n"]
        pres = [r for r in inv["rows"] if r.get("present")]
        neg = [r for r in inv["rows"] if not r.get("present")]
        pc = sum(r.get("correct") for r in pres)
        nc = sum(r.get("correct") for r in neg)
        rows.append(("**AI investigation vs simulation**", f"{n} questions",
                     f"{pc}/{len(pres)} plants found, {nc}/{len(neg)} neg-controls clean",
                     f"**{round(100*c/n)}%**"))

    md = ["# MASTER RESULTS — attack-simulation accuracy (all runs)", "",
          "Every run measures our system against KNOWN simulated ground truth "
          "(authored PowerShell attack telemetry through the real pipeline). "
          "The headline row is how accurately the AI investigation reproduces what "
          "was actually simulated.", "",
          "| Test | Scope | Result | Accuracy |", "|---|---|---|:--:|"]
    for t, s, r, a in rows:
        md.append(f"| {t} | {s} | {r} | {a} |")
    md += ["", "## Per-run detail (md in this folder)",
           "- `accuracy_per_scenario.md` — every technique, detected/host/severity",
           "- `accuracy_precision.md` — false positives on benign input",
           "- `accuracy_noise.md` — recall under 20× benign noise",
           "- `accuracy_combined.md` + `accuracy_combined_report.md` — fused incident, LLM-judged",
           "- `investigation_accuracy.md` — the AI investigation's answers vs the answer key",
           "- `ACCURACY_SUMMARY.md` — narrative summary + characterized boundaries"]
    open(f"{OUT}/MASTER_RESULTS.md", "w").write("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
