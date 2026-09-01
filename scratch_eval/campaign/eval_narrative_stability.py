"""Is the MAIN STORY stable across runs? (the metric that matters per the operator)

Earlier I measured "does the summary mention all 34 techniques" — the wrong question.
The operator's spec is: the summary should convey the MOST LIKELY story and stay
current as the investigation evolves. Enumeration is not the goal.

So this measures NARRATIVE stability instead, over the SAME saved summaries:
  * the leading scenario  — what is scenario #1 about, run to run?
  * the top host          — which host is named as the focus?
  * the top technique     — what is the headline activity?
A stable primary narrative with varying supporting detail is CORRECT behaviour.
A primary narrative that changes run to run is not.

  cd /app/scratch_eval && PYTHONPATH=/app python3 campaign/eval_narrative_stability.py
"""
import glob
import json
import os
import re
import sys
from collections import Counter

OUT = "/tmp/eval_out/campaign"

# the crown-jewel techniques a leading scenario could be built around
THEMES = {
    "credential theft": ["mimikatz", "lsass", "credential dump", "credential theft"],
    "domain compromise": ["dcsync", "ntds", "golden ticket", "adcs", "esc1"],
    "ransomware": ["ransomware", "shadow cop", "vssadmin", "encryption"],
    "exfiltration": ["rclone", "exfiltrat"],
    "C2 / beaconing": ["cobalt strike", "named pipe", "beacon", "c2"],
    "lateral movement": ["lateral", "psexec", "rdp", "svc_backup"],
}


def main():
    files = sorted(glob.glob(f"{OUT}/summary_run_*.md"))
    if not files:
        print("no saved summaries"); return
    lead_theme, lead_host, first_line = Counter(), Counter(), Counter()
    rows = []
    for f in files:
        t = open(f, encoding="utf-8").read()
        low = t.lower()
        # the leading scenario = the first "**1." block, else the Assessment paragraph
        m = re.search(r"\*\*1\.\s*(.+?)\*\*", t)
        lead = (m.group(1) if m else "")[:80]
        # what theme does the FIRST 1200 chars (assessment + scenario 1) centre on?
        head = low[:1200]
        theme = next((k for k, kws in THEMES.items() if any(w in head for w in kws)), "—")
        hosts = re.findall(r"\b(?:WKS|DC|FLEET|AL)[A-Za-z]*-?\w*\d+\b", t[:1200])
        top_host = Counter(hosts).most_common(1)[0][0] if hosts else "—"
        lead_theme[theme] += 1; lead_host[top_host] += 1; first_line[lead] += 1
        rows.append({"file": os.path.basename(f), "lead": lead, "theme": theme,
                     "top_host": top_host})

    n = len(files)
    tstab = lead_theme.most_common(1)[0] if lead_theme else ("—", 0)
    hstab = lead_host.most_common(1)[0] if lead_host else ("—", 0)
    md = ["# Narrative stability — is the MAIN STORY the same each run?", "",
          f"{n} summaries of the SAME case. The operator's spec is 'the most possible "
          "option', not an inventory — so what matters is whether the LEADING story is "
          "consistent, with supporting detail allowed to vary.", "",
          f"- **Leading theme: `{tstab[0]}` in {tstab[1]}/{n} runs**",
          f"- **Top host named: `{hstab[0]}` in {hstab[1]}/{n} runs**",
          f"- distinct leading-scenario titles: **{len(first_line)}**", "",
          "| Run | Leading scenario | Theme | Top host |", "|---|---|---|---|"]
    for r in rows:
        md.append(f"| {r['file'].replace('summary_run_','').replace('.md','')} | "
                  f"{r['lead'][:52]} | {r['theme']} | {r['top_host']} |")
    md += ["", "## Themes across runs", ""]
    for k, v in lead_theme.most_common():
        md.append(f"- {k}: {v}/{n}")
    md += ["", "## Read",
           "Stable theme + stable top host = the analyst gets the same STORY every time, "
           "even though the supporting technique list varies. That is the intended "
           "behaviour for a triage summary. An unstable theme would mean the tool "
           "disagrees with itself about what the incident IS."]
    open(f"{OUT}/narrative_stability.md", "w").write("\n".join(md) + "\n")
    json.dump({"n": n, "themes": dict(lead_theme), "hosts": dict(lead_host),
               "rows": rows}, open(f"{OUT}/narrative_stability.json", "w"), indent=2)
    print("\n".join(md[:9]))
    print()
    for k, v in lead_theme.most_common():
        print(f"   theme {k}: {v}/{n}")


if __name__ == "__main__":
    main()
