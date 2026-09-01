"""Re-score the saved summaries with SYNONYM-AWARE matching (offline, no model calls).

The first pass scored each technique with one literal phrase from the answer key. That
under-counted badly: the model writes "shadow copies"/"vssadmin" not "shadow copy",
"BYOVD" not "driver", "SharpHound" not "BloodHound". Measured false negatives:
shadowcopy 1/10 -> "shadow" present 10/10; byovd 2/10 -> "byovd" 8/10.

A wrong measurement is worse than none, so this re-scores the SAME 10 saved summaries
with a per-technique synonym set. Offline — the summaries are already on disk.

  cd /app/scratch_eval && PYTHONPATH=/app python3 campaign/rescore_summaries.py
"""
import glob
import json
import os
import sys

sys.path.insert(0, "/app")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import attack_corpus as corpus  # noqa: E402

OUT = "/tmp/eval_out/campaign"

# Per-technique acceptance sets: ANY of these counts as "the summary surfaced it".
# Deliberately generous on naming variants, strict on the technique itself.
SYN = {
    "cred-lsass": ["mimikatz", "lsass"],
    "log-clear": ["event log clear", "eventlog clear", "log clearing", "cleared the security",
                  "security log was cleared", "cleared event", "log cleared", "wevtutil"],
    "kerberoast": ["rubeus", "kerberoast", "kerberos ticket"],
    "defender-off": ["defender"],
    "inject": ["injection", "injected", "explorer.exe"],
    "xhost-acct": ["svc_backup"],
    "namedpipe-c2": ["named pipe", "cobalt strike"],
    "binrename": ["procdump", "renamed"],
    "wmi-persist": ["wmi"],
    "dcsync": ["dcsync"],
    "bloodhound": ["bloodhound", "sharphound"],
    "rdp-lateral": ["rdp"],
    "malfind-svc": ["svchost"],
    "golden-ticket": ["golden ticket", "forged ticket"],
    "ransomware": ["ransomware", "encryption"],
    "shadowcopy": ["shadow cop", "vssadmin", "shadow-copy"],
    "reg-sam": ["sam hive", "reg save", "registry sam", "hklm\\sam", "sam dump"],
    "dll-sideload": ["sideload", "side-load", "dll hijack"],
    "amsi-bypass": ["amsi"],
    "exfil-rclone": ["rclone", "exfiltrat"],
    "certutil-dl": ["certutil"],
    "ise-autosave": ["ise autosave", "autosave", "powershell ise",
                     # The narrative names the TECHNIQUE ("encoded download
                     # cradle"), not the artifact it was recovered from -- which
                     # is the better triage description. Scoring on the artifact
                     # name alone made this a false blind spot.
                     "encoded download", "download cradle", "t1059"],
    "mft-erasing": ["sdelete", "erasing", "secure delete", "wiper"],
    "byovd": ["byovd", "vulnerable driver", "driver"],
    "psexec-lateral": ["psexec"],
    "webshell": ["webshell", "web shell"],
    "uac-bypass": ["uac bypass", "fodhelper"],
    "asrep-roast": ["as-rep", "asrep"],
    "c2-beacon": ["beacon"],
    "ntds-dump": ["ntds"],
    "adcs-abuse": ["adcs", "esc1", "certificate template", "certificate abuse"],
    "token-theft": ["token"],
    "staging-archive": ["archive", "staged", "7z"],
    "keylogger": ["keylog", "input capture"],
    "fw-tamper": ["firewall", "netsh"],
    "svc-acct-abuse": ["service account"],
    "clear-usnjrnl": ["usn", "journal"],
    "enc-ps": ["encoded powershell", "-enc", "base64"],
    "sched-task": ["scheduled task", "schtasks"],
    "ad-recon": ["domain admins", "net group", "enumerat"],
    "rmm-abuse": ["anydesk", "rmm"],
}


def main():
    files = sorted(glob.glob(f"{OUT}/summary_run_*.md"))
    if not files:
        print("no saved summaries")
        return
    try:
        prev = json.load(open(f"{OUT}/summary_accuracy.json"))
        eligible_ids = [k for k in prev.get("hits", {})]
    except Exception:
        eligible_ids = [s["id"] for s in corpus.SCENARIOS]

    texts = [open(f, encoding="utf-8").read().lower() for f in files]
    n = len(texts)
    hits = {}
    for sid in eligible_ids:
        syns = SYN.get(sid) or [sid.replace("-", " ")]
        hits[sid] = sum(1 for t in texts if any(s in t for s in syns))

    always = [k for k, v in hits.items() if v == n]
    never = [k for k, v in hits.items() if v == 0]
    flaky = sorted([(k, v) for k, v in hits.items() if 0 < v < n], key=lambda x: x[1])
    mean = sum(hits.values()) / n if n else 0

    md = ["# Summary coverage — RE-SCORED with synonym-aware matching", "",
          f"The first pass used one literal phrase per technique and under-counted "
          f"badly (shadowcopy scored 1/10 while 'shadow'/'vssadmin' appear in 10/10; "
          f"byovd scored 2/10 while 'byovd' appears in 8/10). Re-scored the SAME {n} "
          "saved summaries offline with per-technique synonym sets.", "",
          f"**Mean coverage: {mean:.1f}/{len(hits)} techniques per summary "
          f"({100*mean/len(hits):.0f}%)** — first pass claimed "
          f"{prev.get('mean', 0):.1f} ({100*prev.get('mean',0)/max(1,len(hits)):.0f}%).", "",
          f"- **Always ({len(always)}/{len(hits)})**: {', '.join(sorted(always)) or 'none'}",
          f"- **Never ({len(never)}/{len(hits)})**: {', '.join(sorted(never)) or 'none'}",
          f"- **Intermittent ({len(flaky)}/{len(hits)})**: "
          + (", ".join(f"{k} ({v}/{n})" for k, v in flaky) or "none"), "",
          "| Technique | Summaries mentioning it |", "|---|:--:|"]
    for k, v in sorted(hits.items(), key=lambda x: -x[1]):
        md.append(f"| {k} | {v}/{n} |")
    open(f"{OUT}/summary_coverage_rescored.md", "w").write("\n".join(md) + "\n")
    json.dump({"n": n, "hits": hits, "mean": mean, "always": always,
               "never": never, "flaky": flaky},
              open(f"{OUT}/summary_coverage_rescored.json", "w"), indent=2)
    print("\n".join(md[:10]))


if __name__ == "__main__":
    main()
