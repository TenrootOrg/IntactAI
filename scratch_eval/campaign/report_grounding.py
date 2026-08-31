"""Track D (deterministic part) — grounding sweep over report narratives.

Runs ground_check on each existing report .md against the macro payload the model
was given, and reports UNGROUNDED HASHES as the clean fabrication signal (ungrounded
timestamps are mostly legit proposed zoom-window bounds — noisy, reported but not a
finding). No model call.

  cd /app/scratch_eval && PYTHONPATH=/app python3 campaign/report_grounding.py
"""
import glob
import json
import os
import sys

sys.path.insert(0, "/app")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ground_check  # noqa: E402

OUT = "/tmp/eval_out/campaign"
os.makedirs(OUT, exist_ok=True)
OUTPUTS = "/tmp/eval_out"

# real cases we have report md for -> the case id to rebuild the payload from
REAL = {"case_1788080164853": glob.glob(f"{OUTPUTS}/case_1788080164853__*.md")}


def main():
    print("=== Track D — deterministic grounding sweep ===")
    rows = []
    findings = []
    for cid, mds in REAL.items():
        try:
            payload = ground_check.build_macro_payload(cid)
        except Exception as e:  # noqa: BLE001
            print(f"  payload build failed for {cid}: {e}")
            continue
        for md in sorted(mds):
            name = os.path.basename(md)
            narrative = open(md, encoding="utf-8").read()
            r = ground_check.check(narrative, payload)
            rows.append((name, r))
            bad_h = r["hashes_ungrounded"]
            print(f"  {name}: ts {len(r['timestamps_ungrounded'])}/{r['timestamps_total']} "
                  f"ungrounded (noisy), hashes {len(bad_h)}/{r['hashes_total']} ungrounded"
                  + (f"  !! {bad_h}" if bad_h else ""))
            if bad_h:
                findings.append({
                    "id": f"D-hash-{name}", "title": f"Ungrounded sha256 in {name}",
                    "severity": "medium", "status": "FINDING",
                    "detail": f"hashes not in payload: {bad_h}",
                    "repro": f"ground_check on {name}"})

    json.dump({"track": "D", "rows": [(n, r) for n, r in rows], "findings": findings},
              open(f"{OUT}/report_grounding.json", "w"), indent=2, default=str)
    md = ["# Track D — deterministic grounding sweep", "",
          "Ungrounded **hashes** are the clean fabrication signal; ungrounded "
          "timestamps are mostly legit proposed zoom-window bounds (reported, noisy).",
          "", "| Report | ts ungrounded/total | hashes ungrounded/total |",
          "|---|---|---|"]
    for name, r in rows:
        md.append(f"| {name} | {len(r['timestamps_ungrounded'])}/{r['timestamps_total']} "
                  f"| {len(r['hashes_ungrounded'])}/{r['hashes_total']} |")
    md += ["", f"**{len(findings)} hash-grounding findings.**"]
    open(f"{OUT}/report_grounding.md", "w").write("\n".join(md) + "\n")
    print(f"\n{len(findings)} findings -> {OUT}/report_grounding.md")


if __name__ == "__main__":
    main()
