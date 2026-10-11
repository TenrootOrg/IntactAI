#!/usr/bin/env python3
"""Is masking hiding the right things? Measure both directions before trusting it.

Reading the Log only shows what WAS hidden, so it can never show a leak. On
2026-10-11 this script found three bugs the Log hid: company names were never
masked (Presidio's entity is ORGANIZATION, not ORG), a name right after a JSON \\n
was reported masked but leaked, and one person got two identity numbers.

  cases   Replay each case's Regenerate EXACTLY (same budgets, Jev estimates,
          explicit detail, checklist) with the LLM call stubbed and the case Log
          intercepted -- nothing is sent and nothing is written. Prints what the
          deterministic masker hid and every Presidio hit with the decoded value
          it came from. Lab data has no real people in it: expect 0 Presidio hits.
  probe   Run a payload with real person/company names mixed into the exact
          forensic noise seen on lab reports (scriptblock tails, rule titles,
          field labels, flags) through the live Presidio sidecar, as JSON and as
          plain text. Prints recall (real names hidden) and false positives.

    docker cp scripts/dev/mask_eval.py intact_backend:/tmp/mask_eval.py
    docker exec intact_backend sh -lc 'cd /app && python3 /tmp/mask_eval.py probe'
    docker exec intact_backend sh -lc 'cd /app && python3 /tmp/mask_eval.py cases <case_id>...'
"""
import json
import sys

sys.path.insert(0, "/app")
from services import presidio_masker as pm  # noqa: E402
from services.data_anonymizer import DataAnonymizer  # noqa: E402

NL = chr(10)

REAL = ["Sarah Johnson", "David Okoro", "Maria Gonzalez", "Wei Zhang", "Jean-Luc Picard",
        "Liam O'Connor", "José García", "Emily Carter", "Tom Becker", "Contoso Ltd",
        "Acme Corporation", "Fabrikam Inc", "Northwind Traders", "Woodgrove Bank",
        "First Security Bank", "PayPal Inc", "LinkedIn Corporation"]
NOISE = ["Infrastr", "Firewal", "Valu", "LogonId", "MethodPara", "PSScriptPolicyTest",
         "-NoProfile", "Bypass", "Trojan", "Creating Scriptblock", "Remote Desktop Services",
         "Group Policy", "Certificate Authority", "Microsoft Corporation", "SCM Event Provider",
         "Possiblecause", "IMPHASH", "SSH", "ioc", "param", "Microso", "Systeminfo",
         "Important Windows Eventlog Cleared", "Archive Utilities", "New Firewall Rule",
         "Uncommon Process", "Defau", "Domain Name", "Account Name", "Logon ID", "Security ID"]
PAYLOAD = {
    "findings": [
        {"title": "SIGMA: Suspicious Execution of Systeminfo 2 on Hostname1",
         "summary": "Creating Scriptblock text (21 of 24):\nft.Management.Infrastr",
         "label": "Creating Scriptblock text (13 of 20):\ntFirewallServiceFilter"},
        {"title": "SIGMA: Important Windows Eventlog Cleared (+1 related)",
         "summary": "Threat: Trojan:Win32/Bearfoos.B!ml · Process: powershell.exe "
                    "-NoProfile -NonInteractive -ExecutionPolicy Bypass"},
        {"summary": "DisableAliases = 2 DefaultToStaticType = 16 OmitNullValues = 64 OmitNullValu"},
        {"summary": "$x.LogonId; $m.MethodPara; PSScriptPolicyTest Creation By Uncommon Process"},
        {"summary": "Provider: SCM Event Provider · Possiblecause: Permanent · IMPHASH=63CB8EC851"},
        {"summary": "Added Rule: SSH from Intact; type ioc; param(\r\n  [switch]$Force, 'Defau"},
        {"summary": "Burst — New Firewall Rule Added In Windows Firewall, MFT: Archive Utilities"},
        {"summary": "Signed by Microsoft Corporation; issuer Certificate Authority; O=Woodgrove Bank"},
        {"summary": "Remote Desktop Services started; Group Policy refreshed on Hostname1 (Microso"},
        {"summary": "Microsoft-Windows-Sysmon/Operational"},
    ],
    "analyst_notes": "Escalated by Sarah Johnson.\nDavid Okoro confirmed the host belongs to Contoso Ltd.",
    "manual_events": [
        {"note": "Call with Maria Gonzalez from Acme Corporation about the incident."},
        {"note": "\"Wei Zhang\" (Northwind Traders) sent the phishing email."},
        {"note": "Jean-Luc Picard and Liam O'Connor of Fabrikam Inc approved isolation."},
        {"note": "José García reported the laptop stolen; Emily (IT) said Emily Carter has the spare."},
        {"note": "From: Tom Becker <tbecker@example.com>\r\nSubject: invoice"},
        {"note": "Wire sent to First Security Bank; vendors PayPal Inc and LinkedIn Corporation notified."},
    ],
}
TECH = frozenset({"suspicious execution of systeminfo 2", "important windows eventlog cleared",
                  "archive utilities", "new firewall rule added in windows firewall",
                  "psscriptpolicytest creation by uncommon process"})
NARRATIVE = ("The audit record identifies Account Name `attacked-win11`, Domain Name "
             "`DESKTOP-2175T02`, Logon ID `64592230`, Security ID `S-1-5-21-1`. Sarah Johnson "
             "escalated it; First Security Bank and PayPal Inc were notified.")


def _mask():
    m = DataAnonymizer()
    m._ner = True
    m._tech_phrases = TECH
    return m


def probe():
    out, hits = pm.scrub(json.dumps(PAYLOAD), _mask(), logfn=lambda *a, **k: None)
    masked = sorted({h["text"] for h in hits})
    flat = json.dumps(json.loads(out), ensure_ascii=False)
    still = [n for n in REAL if n in flat]
    fp = [n for n in NOISE if any(n == h or n in h for h in masked)]
    print("JSON  hits:", masked)
    print(f"JSON  RECALL {len(REAL) - len(still)}/{len(REAL)} — still visible: {still}")
    print(f"JSON  FALSE POSITIVES {len(fp)}/{len(NOISE)}: {fp}")
    out2, hits2 = pm.scrub(NARRATIVE, _mask(), logfn=lambda *a, **k: None)
    real2 = ["Sarah Johnson", "First Security Bank", "PayPal Inc"]
    noise2 = ["Domain Name", "Account Name", "Logon ID", "Security ID"]
    h2 = {h["text"] for h in hits2}
    print(f"PLAIN RECALL {sum(n not in out2 for n in real2)}/{len(real2)} — "
          f"FALSE POSITIVES: {[n for n in noise2 if any(n in h for h in h2)]}")


def cases(ids):
    from services.fusion import store, llm_sim
    logs, hits = [], []
    store.log_case_event = lambda cid, act, lvl="info", msg="", **kw: logs.append((act, str(msg)))
    llm_sim._real_llm = lambda *a, **k: "stub narrative"      # nothing leaves the box
    orig = pm.scrub

    def spy(text, mask=None, **kw):
        out, h = orig(text, mask, **kw)
        det = pm._detection_text(text) if h else ""
        for x in h:
            line = next((ln for ln in det.split(NL) if x["text"] in ln), "")
            j = line.find(x["text"])
            hits.append((x["text"], x["type"], x["pseudo"], line[max(0, j - 70):j + len(x["text"]) + 25]))
        return out, h
    pm.scrub = spy
    for cid in ids:
        logs.clear()
        hits.clear()
        d = store.get_case(cid)
        gv = store.view_graph(cid, d)
        mask = store._case_mask(cid, d)
        if mask is not None:
            mask._logfn = lambda m, l="info": None
        ent, chars = store._llm_payload_budget(d)
        try:
            llm_sim.generate_report(
                gv, estimates=store._jev_estimates(cid, d, gv, True), window=store.view_window(d),
                min_severity=d.get("min_severity") or "informational",
                initial_access=d.get("initial_access_estimate"), case_name=d.get("name", "Case"),
                run_id=cid, audience=d.get("audience", "both"), language=d.get("language", "en"),
                altitude_mode=d.get("report_altitude") or "auto", master_prompt=d.get("master_prompt"),
                mask=mask, dispositions=d.get("dispositions") or None,
                validations=d.get("timeline_validations") or None,
                manual_events=d.get("manual_timeline_events") or None,
                checklist=d.get("disposition_checklist") or None, prefer_llm=True,
                max_entities=ent, budget_chars=chars, max_output_tokens=store._effective_output_cap(d),
                detail="explicit", max_identities=store._llm_identity_budget(d))
        except Exception as e:  # noqa: BLE001
            print("generate_report error:", e)
        print(NL + "### " + cid + " — " + str(d.get("name")))
        for act, msg in logs:
            if act.startswith("Masking · custom"):
                print("  " + msg.replace(NL, NL + "  "))
        for t, ty, ps, ctx in dict.fromkeys(hits):
            print("  PRESIDIO %s %r=%s  in: %r" % (ty, t, ps, ctx))
        if not hits:
            print("  Presidio: no hits")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "cases":
        cases(sys.argv[2:])
    else:
        probe()
