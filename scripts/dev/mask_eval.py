#!/usr/bin/env python3
"""Is masking hiding the right things? Measure both directions before trusting it.

Reading the Log only shows what WAS hidden, so it can never show a leak. On
2026-10-11 this script found three bugs the Log hid: company names were never
masked (Presidio's entity is ORGANIZATION, not ORG), a name right after a JSON \\n
was reported masked but leaked, and one person got two identity numbers.

  cases   Replay each case's Regenerate EXACTLY (same budgets, decision-model estimates,
          explicit detail, checklist) with the LLM call stubbed and the case Log
          intercepted -- nothing is sent and nothing is written. Prints what the
          deterministic masker hid and every Presidio hit with the decoded value
          it came from. Lab data has no real people in it: expect 0 Presidio hits.
  leaks   Capture the exact masked text every model call of a case would get and
          list what is still visible: the case's own accounts, hosts (with former
          names) and IPs, plus anything identifier-shaped (internal FQDNs, private
          IPs, default DESKTOP-/WIN- names). Found five gaps on a 9-host case.
  probe   Run a payload with real person/company names mixed into the exact
          forensic noise seen on lab reports (scriptblock tails, rule titles,
          field labels, flags) through the live Presidio sidecar, as JSON and as
          plain text. Prints recall (real names hidden) and false positives.

  corpus  A labelled stress test of both layers on a synthetic company: identities
          in every form and glued to JSON escapes / Hebrew / URL encoding, next to
          words that must survive (case names that are English words, rule titles,
          threat actors, versions shaped like IPs). Scores leaks AND over-masking per
          category, deterministic layer alone and with Presidio. Nothing is written.

    docker cp scripts/dev/mask_eval.py intact_backend:/tmp/mask_eval.py
    docker exec intact_backend sh -lc 'cd /app && python3 /tmp/mask_eval.py corpus'
    docker exec intact_backend sh -lc 'cd /app && python3 /tmp/mask_eval.py probe'
    docker exec intact_backend sh -lc 'cd /app && python3 /tmp/mask_eval.py cases <case_id>...'
    docker exec intact_backend sh -lc 'cd /app && python3 /tmp/mask_eval.py leaks <case_id>'
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
                gv, estimates=store._decision_estimates(cid, d, gv, True), window=store.view_window(d),
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


def leaks(cid):
    import re
    from services.fusion import store, llm_sim
    sent = []
    store.log_case_event = lambda *a, **k: None
    llm_sim._real_llm = lambda system, user, *a, **k: (sent.append(user), "stub narrative")[1]
    d = store.get_case(cid)
    gv = store.view_graph(cid, d)
    mask = store._case_mask(cid, d)
    if mask is not None:
        mask._logfn = lambda *a, **k: None
    ent, chars = store._llm_payload_budget(d)
    llm_sim.generate_report(
        gv, window=store.view_window(d), min_severity=d.get("min_severity") or "informational",
        run_id=cid, mask=mask, prefer_llm=True, max_entities=ent, budget_chars=chars,
        detail="explicit", max_identities=store._llm_identity_budget(d))
    blob = NL.join(sent)
    print(f"{len(sent)} model call(s), {len(blob):,} chars sent")
    known = set()
    for e in gv.entities.values():
        if e.type == "account":
            known.add(e.label.split("\\")[-1].split("@")[0])
        elif e.type == "asset":
            known.add(e.label)
            for h in (e.attrs or {}).get("name_history") or []:
                known.add(str(h.get("name") if isinstance(h, dict) else h))
        elif e.type in ("netconn", "ioc") and re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", e.label or ""):
            known.add(e.label)
    skip = {"null", "none", "administrator", "guest", "system", "user", "defaultaccount",
            "wdagutilityaccount", "local service", "network service"}
    vis = sorted(v for v in known if len(v) >= 3 and v.lower() not in skip and re.search(
        r"(?<![\w-])" + re.escape(v) + r"(?![\w-])", blob, re.I))
    print(f"case identifiers still visible: {len(vis)} of {len(known)}", vis[:20])
    shapes = {"internal FQDN": r"(?i)\b(?:[a-z0-9-]+\.)+(?:local|lan|corp|internal|intranet)\b",
              "private IP": r"\b(?:10\.\d+|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d+\.\d+\b",
              "default host name": r"\b(?:DESKTOP|WIN|LAPTOP)-[A-Z0-9]{5,}\b"}
    for k, rx in shapes.items():
        hits = sorted(set(re.findall(rx, blob)))
        print(f"{k:18} still visible: {len(hits)}", hits[:10])


# ---------------------------------------------------------------------------
# corpus: a labelled stress test of BOTH layers on a synthetic company ("Galil").
# Every line says what must be hidden and what must survive verbatim. Masking a
# word the model needs ("will", "backup", a rule title, a version) changes what it
# concludes, so over-masking is scored as hard as a leak. Each line is run in the
# three shapes production produces: its own JSON value, a line after a JSON \n
# inside a longer value, and plain text (chat).
# ---------------------------------------------------------------------------
SID_U = "S-1-5-21-3623811015-3361044348-30300820-1013"
CORPUS = [
    # -- identities the graph knows (deterministic layer's job)
    ("Account GALIL\\dana.levi logged on to GL-WS-014 from 10.20.30.40.",
     ["acct:GALIL\\dana.levi", "acct:dana.levi", "host:GL-WS-014", "ip:10.20.30.40", "dom:GALIL"], []),
    ("dana.levi reset the password at 08:14.", ["acct:dana.levi"], ["tech:reset the password"]),
    ("UPN dana.levi@galil-dyn.co.il signed in.", ["acct:dana.levi@galil-dyn.co.il", "dom:galil-dyn.co.il"], []),
    ("Case variants: DANA.LEVI on gl-ws-014 and Gl-Ws-014.", ["acct:DANA.LEVI", "host:gl-ws-014", "host:Gl-Ws-014"], []),
    ("dana.levi's mailbox and GLDC01's NTDS were read.", ["acct:dana.levi", "host:GLDC01"], ["tech:NTDS"]),
    ("Renamed from DESKTOP-K7Q2M9X; DC GLDC01 (gldc01.galil.local).",
     ["host:DESKTOP-K7Q2M9X", "host:GLDC01", "host:gldc01.galil.local", "dom:galil.local"], []),
    ("Machine account GL-WS-014$ authenticated to GLDC01.", ["host:GL-WS-014", "host:GLDC01"], []),
    ("Service PAExec-7032-FINANCE-PC was created.", ["host:FINANCE-PC"], ["tool:PAExec"]),
    ("Dropped C:\\Users\\dana.levi\\AppData\\Roaming\\upd.dll", ["acct:dana.levi"],
     ["path:C:\\Users\\", "path:AppData\\Roaming\\upd.dll"]),
    ("Lateral: net use \\\\FILESRV01\\c$ /user:GALIL\\dana.levi Winter2026!",
     ["host:FILESRV01", "acct:GALIL\\dana.levi", "secret:Winter2026!"], ["tech:net use"]),
    ("wmic /node:192.168.5.12 process call create", ["ip:192.168.5.12"], ["tool:wmic"]),
    ("Query ldap://gldc01.galil.local:389 for admins", ["host:gldc01.galil.local"], ["tech:ldap://"]),
    ("Account GALIL\\amit.cohen and svc_backup ran the job.", ["acct:GALIL\\amit.cohen", "acct:svc_backup"], []),
    ("Owner SID " + SID_U + " holds the key.", ["sid:" + SID_U], []),
    ("DN CN=Dana Levi,OU=Finance,DC=galil,DC=local", ["person:Dana Levi", "dom:galil"], ["tech:OU=Finance"]),
    ("Proxy log: GET /sso?user=GALIL%5Cdana.levi", ["acct:dana.levi"], ["tech:GET /sso?user="]),
    ("Host table:\tGL-WS-014\tFINANCE-PC", ["host:GL-WS-014", "host:FINANCE-PC"], []),
    # -- free text only NER can catch (not a graph entity)
    ("Escalated by Yossi Cohen of Galil Dynamics Ltd; Bank Hapoalim was notified.",
     ["person:Yossi Cohen", "org:Galil Dynamics Ltd", "org:Bank Hapoalim"], []),
    ("Mail from yossi.mizrahi@partner-law.co.il about the invoice.", ["email:yossi.mizrahi@partner-law.co.il"], []),
    ("Dana Levi confirmed she clicked the link.", ["person:Dana Levi"], []),
    # -- common words that are ALSO this case's account/host names (must survive)
    ("The attacker will likely return, so we will monitor.", [], ["word:attacker will likely", "word:we will monitor"]),
    ("Mark-of-the-Web was stripped; mark the file as malicious.", [], ["word:Mark-of-the-Web", "word:mark the file"]),
    ("Backup job failed after the shadow copies were deleted; Veeam Backup stopped.",
     [], ["word:Backup job", "product:Veeam Backup"]),
    ("A port scan preceded the web shell upload to the IIS web server.",
     [], ["word:port scan", "word:web shell", "word:web server"]),
    # -- threat intel and machine text (must survive verbatim)
    ("mimikatz sekurlsa::logonpasswords read lsass.exe (T1003.001); Rubeus, BloodHound and PsExec followed.",
     [], ["tool:mimikatz", "tool:sekurlsa::logonpasswords", "proc:lsass.exe", "mitre:T1003.001",
          "tool:Rubeus", "tool:BloodHound", "tool:PsExec"]),
    ("Cobalt Strike beacon to update-msft-cdn.com; LockBit 3.0 note; Emotet loader.",
     [], ["tool:Cobalt Strike", "ioc:update-msft-cdn.com", "malware:LockBit 3.0", "malware:Emotet"]),
    ("Overlaps APT29, Lazarus Group, MuddyWater and Agrius; CVE-2023-23397, KB5034441, TA0008.",
     [], ["actor:APT29", "actor:Lazarus Group", "actor:MuddyWater", "actor:Agrius",
          "mitre:CVE-2023-23397", "mitre:KB5034441", "mitre:TA0008"]),
    ("Rules: Suspicious Backup Deletion via Wbadmin; Mimikatz Use; Shadow Copies Deletion Using Operating Systems Utilities.",
     [], ["rule:Suspicious Backup Deletion via Wbadmin", "rule:Mimikatz Use",
          "rule:Shadow Copies Deletion Using Operating Systems Utilities"]),
    ("Built-ins: NT AUTHORITY\\SYSTEM, Administrator, krbtgt, Domain Admins, LOCAL SERVICE, DefaultAccount.",
     [], ["builtin:NT AUTHORITY\\SYSTEM", "builtin:Administrator", "builtin:krbtgt", "builtin:Domain Admins",
          "builtin:LOCAL SERVICE", "builtin:DefaultAccount"]),
    ("Well-known SIDs S-1-5-18 and S-1-5-32-544.", [], ["sid-builtin:S-1-5-18", "sid-builtin:S-1-5-32-544"]),
    ("Microsoft Defender, CrowdStrike Falcon, SentinelOne and Sysmon on Windows Server 2019.",
     [], ["product:Microsoft Defender", "product:CrowdStrike Falcon", "product:SentinelOne",
          "product:Sysmon", "product:Windows Server 2019"]),
    ("powershell.exe -nop -w hidden; rundll32.exe; wbadmin.exe delete catalog; vssadmin.exe delete shadows",
     [], ["proc:powershell.exe -nop -w hidden", "proc:rundll32.exe", "proc:wbadmin.exe delete catalog",
          "proc:vssadmin.exe delete shadows"]),
    ("SHA256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 MD5 5d41402abc4b2a76b9719d911017c592 "
     "CLSID {6F9619FF-8B86-D011-B42D-00C04FC964FF}",
     [], ["hash:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
          "hash:5d41402abc4b2a76b9719d911017c592", "guid:6F9619FF-8B86-D011-B42D-00C04FC964FF"]),
    ("Build 10.0.19045.3803, FileVersion 10.0.17763.1, ProductVersion 2.0.0.1; RDP 3389, SMB 445.",
     [], ["version:10.0.19045.3803", "version:10.0.17763.1", "version:2.0.0.1", "port:3389", "port:445"]),
    ("First seen 2026-10-12T08:14:03Z, last seen 12/10/2026 09:15.", [], ["date:2026-10-12T08:14:03Z", "date:12/10/2026 09:15"]),
    # -- Hebrew: must not break, and identifiers inside it are still hidden
    ("הערת אנליסט: המשתמש dana.levi התחבר מ-GL-WS-014 בשעה 08:14",
     ["acct:dana.levi", "host:GL-WS-014"], ["hebrew:הערת אנליסט: המשתמש", "hebrew:התחבר", "hebrew:בשעה 08:14"]),
    ("הקובץ חשבונית_אוקטובר.pdf נשלח לdana.levi", ["acct:dana.levi"], ["hebrew:הקובץ חשבונית_אוקטובר.pdf נשלח"]),
    ("דנה לוי מצוות הכספים דיווחה על המייל", ["hebrew-name:דנה לוי"], ["hebrew:מצוות הכספים דיווחה על המייל"]),
]


def _corpus_graph():
    from services.fusion.schema import Entity, FusionGraph
    g = FusionGraph(case_id="corpus")

    def add(t, label, attrs=None, flags=None):
        e = Entity(id=f"{t}:{len(g.entities)}", type=t, label=label, attrs=attrs or {}, flags=flags or [])
        g.entities[e.id] = e
    add("asset", "GL-WS-014", {"name_history": ["DESKTOP-K7Q2M9X"]})
    for h in ("GLDC01.galil.local", "BACKUP", "WEB", "FINANCE-PC"):
        add("asset", h)
    for a in ("GALIL\\dana.levi", "dana.levi@galil-dyn.co.il", "GALIL\\will", "GALIL\\mark", "svc_backup",
              "GALIL\\scan", "GALIL\\Administrator", "NT AUTHORITY\\SYSTEM", "krbtgt", "GALIL\\amit.cohen"):
        add("account", a)
    add("netconn", "10.20.30.40")
    add("ioc", "update-msft-cdn.com", {"ioc_kind": "domain"})
    for r in ("Suspicious Backup Deletion via Wbadmin", "Mimikatz Use",
              "Shadow Copies Deletion Using Operating Systems Utilities"):
        add("event", r, {"title": r}, ["sigma"])
    add("event", "net use", {"ev_user": "GALIL\\dana.levi", "ev_cmdline":
        "net use \\\\FILESRV01\\c$ /user:GALIL\\dana.levi Winter2026! & wmic /node:192.168.5.12 process call create"})
    add("event", "ldap query", {"details": "ldap://gldc01.galil.local:389 ProductVersion 2.0.0.1 FileVersion 10.0.17763.1"})
    return g


def _visible(tok, text, keep):
    # Kept text must survive EXACTLY; a leak is ANY occurrence, glued or not --
    # a boundary check here would share the masker's own blind spots.
    return tok in text if keep else tok.lower() in text.lower()


def corpus():
    from services.fusion import llm_sim
    g = _corpus_graph()
    lines = [t for t, _, _ in CORPUS]

    def run(ner):
        m = DataAnonymizer()
        m._ner = ner
        m._logfn = lambda *a, **k: None
        llm_sim._build_mask_mapping(g, m)
        out = {}
        # (1) each line its own JSON value; (2) lines after a JSON \n in one long value
        pay = json.dumps({"findings": [{"summary": t} for t in lines], "analyst_notes": NL.join(lines)})
        try:
            d = json.loads(llm_sim._apply_mask(pay, m, ner=ner))
            out["json"] = [f["summary"] for f in d["findings"]]
            out["json-after-\\n"] = d["analyst_notes"].split(NL)
        except Exception as e:  # noqa: BLE001
            print("  JSON CRASH:", type(e).__name__, e)
        # (3) plain text, as chat sends it
        try:
            out["plain"] = llm_sim._apply_mask(NL.join(lines), m, ner=ner).split(NL)
        except Exception as e:  # noqa: BLE001
            print("  PLAIN CRASH:", type(e).__name__, e)
        return m, out

    for ner in (False, True):
        m, out = run(ner)
        print(NL + "=" * 78 + NL + ("DETERMINISTIC + PRESIDIO" if ner else "DETERMINISTIC ONLY (ner off)"))
        if ner and getattr(m, "_ner_failed", False):
            print("  !! Presidio did not answer -- NER results below are NOT real")
        score, fails = {}, []
        for shape, got in out.items():
            if len(got) != len(lines):
                fails.append((shape, "-", "LINE COUNT", f"{len(got)} != {len(lines)}"))
                continue
            for i, ((src, mask_t, keep_t), res) in enumerate(zip(CORPUS, got)):
                for spec, keep in [(x, False) for x in mask_t] + [(x, True) for x in keep_t]:
                    cat, tok = spec.split(":", 1)
                    ok = _visible(tok, res, keep) == keep
                    s = score.setdefault((("KEEP " if keep else "MASK ") + cat), [0, 0])
                    s[0] += ok
                    s[1] += 1
                    if not ok:
                        fails.append((shape, cat, "DAMAGED" if keep else "LEAKED", tok, i, res))
        for k in sorted(score):
            ok, n = score[k]
            flag = "" if ok == n else "   <--"
            print(f"  {k:22} {ok:3}/{n:<3}{flag}")
        seen = set()
        for f in fails:
            key = f[1:5]
            if key in seen:
                continue
            seen.add(key)
            shapes = sorted({x[0] for x in fails if x[1:5] == key})
            print(f"  {f[2]:8} {f[1]}:{f[3]!r} in {shapes}{NL}           -> {f[5] if len(f) > 5 else ''}")
        # One person, one number: every form of dana.levi must share it.
        import re
        forms = {k: v for k, v in m.mapping.items() if "dana.levi" in k.lower()}
        nums = {re.sub(r"\D", "", v) for v in forms.values()}
        print(f"  identity numbers for dana.levi's forms: {sorted(nums)} {'OK' if len(nums) == 1 else '<-- SPLIT'}")
        if not ner:
            print("  mapping:", NL + NL.join(f"    {k!r} = {v}" for k, v in sorted(m.mapping.items(), key=lambda x: x[1])))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "corpus":
        corpus()
    elif len(sys.argv) > 1 and sys.argv[1] == "cases":
        cases(sys.argv[2:])
    elif len(sys.argv) > 2 and sys.argv[1] == "leaks":
        leaks(sys.argv[2])
    else:
        probe()
