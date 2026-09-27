"""Every analyst input reaches every output — on a LIVE appliance, on a copy.

Runs INSIDE the backend container (tests/test_case_integration_live.py copies it
in and runs it). It never touches the source case: it creates a throwaway case
that reads the source case's runs, drives it through the same HTTP routes the
page uses, and deletes it at the end — first unlisting the runs, so the delete
cannot reach the source case's evidence (store.delete_case also refuses to).

Inputs (what the analyst does)          Outputs (where it must show)
  Timeline: True/False Positive, group    Timeline, Risk, Identities
  Timeline: manual event                  the deterministic (no-LLM) report
  Identities: Compromised / Not           what the report model is sent
  Configuration: exclude a host           what the chat model is sent
  Chat: "that's our IT admin" + confirm   the chat's own disposition flow

The model is NOT called in the default run: _real_llm is replaced in a separate
process to record exactly what the report / chat would be sent. `--llm` adds one
real chat answer and one real report and checks (softly) that they use the input.

    python3 live_case_integration.py <source_case_id> [--llm]
Exit 0 = every hard check passed.
"""
import json
import sys
import time
import traceback
import urllib.error
import urllib.request

sys.path.insert(0, "/app")
B = "http://127.0.0.1:5001"
SRC = sys.argv[1]
LLM = "--llm" in sys.argv
RESULTS = []


def call(method, path, body=None, timeout=900):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(B + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
    except urllib.error.HTTPError as e:
        raw = e.read()
    try:
        return json.loads(raw or b"{}")
    except ValueError:
        return {"_raw": raw[:200].decode("utf-8", "replace")}


def check(name, ok, detail=""):
    RESULTS.append(("ok" if ok else "FAIL", name, detail))
    print(("  ok    " if ok else "  FAIL  ") + name + ("" if ok or not detail else f"  — {detail}"), flush=True)
    return ok


def soft(name, ok, detail=""):
    RESULTS.append(("ok" if ok else "WARN", name, detail))
    print(("  ok    " if ok else "  WARN  ") + name + ("" if ok or not detail else f"  — {detail}"), flush=True)


def section(t):
    print(f"\n== {t}", flush=True)


def timeline(cid):
    t = call("GET", f"/api/cases/{cid}/timeline")
    return t.get("timeline", t) if isinstance(t, dict) else t


def risk(cid):
    return call("GET", f"/api/cases/{cid}/risk").get("rows") or []


def people(cid):
    return call("GET", f"/api/cases/{cid}/identities").get("identities") or []


def det_name(title):
    """The detection a row is an episode of — the name fusion counts by
    (correlate._detection_name): no host, no "(+N related)" / "(recurring …)"."""
    from services.fusion.correlate import _RELATED_SUFFIX
    return _RELATED_SUFFIX.sub("", title.rsplit(" on ", 1)[0]).strip()


def report_md(cid):
    call("POST", f"/api/cases/{cid}/report", {"use_llm": False})
    return call("GET", f"/api/cases/{cid}/report").get("report_md") or ""


def captured_model_input(cid, question=None):
    """What the model would be sent: run the REAL report / chat code with the
    model call replaced by a recorder, in a child process (the service is not
    patched). Returns the concatenated prompts."""
    import subprocess
    code = f"""
import sys, json; sys.path.insert(0, "/app")
from services.fusion import llm_sim, store, jev
sent = []
def fake(system, user, **kw):
    sent.append(str(system) + "\\n" + str(user)); return "## Executive Summary\\nstub.\\n**Risk: HIGH** — stub."
llm_sim._real_llm = fake
llm_sim._llm_available = lambda: True
jev.enabled = lambda *a, **k: False
q = {question!r}
try:
    if q: store.chat_case({cid!r}, q)
    else: store.regenerate_report({cid!r}, use_llm=True, offline=False)
except Exception as e:
    print("CAPTURE-ERROR", type(e).__name__, e, file=sys.stderr)
print(json.dumps(sent))
"""
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=900)
    try:
        last = [ln for ln in out.stdout.splitlines() if ln.startswith("[")][-1]
        return "\n".join(json.loads(last)), out.stderr[-600:]
    except Exception:  # noqa: BLE001
        return "", (out.stderr or out.stdout)[-600:]


def main():
    from services.fusion import store
    from services import workflow_service as ws
    from services.file_storage_service import get_workflow

    sd = store.get_case(SRC)
    assert sd, f"source case {SRC} not found"
    runs = list(sd.get("fused_run_ids") or [])
    src_rows = len(timeline(SRC))
    print(f"source {SRC}: {len(runs)} run(s), {src_rows} timeline rows")

    cid = call("POST", "/api/cases", {
        "name": f"itest-{int(time.time())}", "member_run_ids": runs,
        "min_severity": sd.get("min_severity") or "medium",
        "time_window": sd.get("time_window") or {}})["case_id"]
    print(f"throwaway case {cid}")
    try:
        section("0. the copy is the same case")
        f = call("POST", f"/api/cases/{cid}/fuse")
        rows = timeline(cid)
        check("fuse succeeded", f.get("status") == "fused", str(f)[:200])
        check("same timeline rows as the source", len(rows) == src_rows, f"{len(rows)} vs {src_rows}")
        rk = risk(cid)
        check("risk ranks hosts", len(rk) >= 2, f"{len(rk)} hosts")
        ppl = people(cid)
        check("identities resolve people", len(ppl) >= 2, f"{len(ppl)} people")

        # ---- choose targets from the data itself ---------------------------
        h1 = rk[0]["host"]
        # A detection with ONE row on the host: a False Positive on one episode of a
        # detection with eight must not (and does not) remove the detection.
        by_det = {}
        for r in rows:
            if r.get("source") == "fusion" and h1 in [h.strip() for h in (r.get("host") or "").split(",")]:
                by_det.setdefault(det_name(r["title"]), []).append(r)
        # …and not critical: a benign verdict never down-ranks a critical finding
        # (deliberate — see tests/test_disposition_suppression.py), so a critical
        # False Positive stays counted, annotated "surfaced anyway for review".
        singles = [v[0] for v in by_det.values() if len(v) == 1 and not v[0].get("group")
                   and v[0].get("host") == h1 and v[0].get("severity") != "critical"]
        singles.sort(key=lambda r: ["critical", "high", "medium", "low", "informational"].index(r.get("severity", "low")))
        fa, fb = singles[0], singles[1]
        grp_ids = {}
        for r in rows:
            if (r.get("group") or {}).get("id"):
                grp_ids.setdefault(r["group"]["id"], []).append(r["finding_id"])
        gid, gmembers = next((k, v) for k, v in grp_ids.items() if len(v) >= 2)
        withf = [p for p in ppl if p.get("detections") and not p.get("builtin")]
        pp, pq = withf[0], withf[1]
        hx = rk[-1]["host"]
        print(f"targets: host {h1} | TP {fa['title'][:60]} | FP {fb['title'][:60]} | group {gid} ({len(gmembers)} rows) "
              f"| compromised {pp['name']} | not {pq['name']} | exclude {hx}")
        risk_before = next(r for r in rk if r["host"] == h1)

        section("1. Timeline verdicts")
        call("POST", f"/api/cases/{cid}/timeline/validate", {"finding_id": fa["finding_id"], "status": "true_positive"})
        call("POST", f"/api/cases/{cid}/timeline/validate", {"finding_id": fb["finding_id"], "status": "false_positive"})
        call("POST", f"/api/cases/{cid}/timeline/validate", {"finding_ids": gmembers, "status": "known"})
        rows = timeline(cid)
        v = {r["finding_id"]: r.get("validation") for r in rows}
        check("True Positive shows on its row", v.get(fa["finding_id"]) == "true_positive")
        check("False Positive shows on its row", v.get(fb["finding_id"]) == "false_positive")
        check("a group verdict sets every row in the group", all(v.get(i) == "known" for i in gmembers),
              str([v.get(i) for i in gmembers]))
        after = next((r for r in risk(cid) if r["host"] == h1), {})
        check("Risk: a False Positive detection stops counting for its host",
              after.get("finding_count", 0) == risk_before["finding_count"] - 1,
              f"distinct detections {risk_before['finding_count']} -> {after.get('finding_count')}")
        check("Risk: the False Positive is no longer a reason for the host",
              det_name(fb["title"]) not in (after.get("why") or ""), (after.get("why") or "")[:160])

        section("2. Manual Timeline event")
        manual_title = "ITEST manual: analyst confirmed RDP from the jump host"
        call("POST", f"/api/cases/{cid}/timeline/event",
             {"ts": fa.get("ts") or "2025-06-01T10:00:00Z", "host": h1, "title": manual_title, "severity": "high"})
        check("the manual event is on the Timeline", any(r.get("title") == manual_title for r in timeline(cid)))

        section("3. Identities verdicts")
        acc = lambda p: [a["id"] for a in p["accounts"]]  # noqa: E731
        call("POST", f"/api/cases/{cid}/identities/verdict", {"account_ids": acc(pp), "verdict": "compromised", "name": pp["name"]})
        call("POST", f"/api/cases/{cid}/identities/verdict", {"account_ids": acc(pq), "verdict": "not_compromised", "name": pq["name"]})
        ppl = people(cid)
        vv = {p["name"]: p.get("verdict") for p in ppl}
        check("Identities: the verdicts show on the cards",
              vv.get(pp["name"]) == "compromised" and vv.get(pq["name"]) == "not_compromised", str(vv)[:200])
        check("Identities: people you marked come first", [p["name"] for p in ppl[:2]] == [pp["name"], pq["name"]],
              str([p["name"] for p in ppl[:3]]))
        check("Risk ↔ Identities: the compromised person is on the hosts they were seen on",
              any(h in [r["host"] for r in risk(cid)] for h in pp.get("seen_on") or []))

        section("3b. Jev reacts to your verdicts (when Jev is on)")
        from services.fusion import jev as _jev
        if _jev.enabled("compromise"):
            tgt_p = next((p for p in people(cid) if p.get("findings") and p["name"] not in (pp["name"], pq["name"])), None)
            if tgt_p:
                k0 = set((store.get_case(cid) or {}).get("jev_compromise") or {})
                fid = tgt_p["findings"][0]["id"]
                call("POST", f"/api/cases/{cid}/timeline/validate", {"finding_id": fid, "status": "false_positive"})
                new_key = False
                for _ in range(36):                      # the post-fuse Jev pass is asynchronous
                    time.sleep(5)
                    if set((store.get_case(cid) or {}).get("jev_compromise") or {}) - k0:
                        new_key = True
                        break
                check(f"a False Positive on {tgt_p['name']}'s finding makes Jev re-estimate them", new_key)
                cur = next((p for p in people(cid) if p["name"] == tgt_p["name"]), {})
                check("… and the card shows the new estimate", isinstance(cur.get("jev_compromise"), (int, float)),
                      str(cur.get("jev_compromise")))
        else:
            print("  (skipped: Jev's compromise estimate is off)")

        section("4. The deterministic (no-LLM) report")
        md = report_md(cid)
        check("report written", len(md) > 500, f"{len(md)} chars")
        check("lists the True Positive", fa["title"] in md)
        check("lists the False Positive", fb["title"] in md)
        check("lists the person marked compromised", f"Identities marked compromised" in md and pp["name"] in md)
        check("tells you to reset their credentials", "Treat these identities as compromised" in md)
        check("includes the manual Timeline event", manual_title in md)

        section("5. What the report model is sent")
        sent, err = captured_model_input(cid)
        check("the report was sent to the model", len(sent) > 1000, err)
        check("… with the Timeline verdicts", fa["title"] in sent and fb["title"] in sent)
        check("… with the person marked compromised", "analyst_identity_verdicts" in sent and pp["name"] in sent)
        check("… with the manual event", manual_title in sent)

        section("6. What the chat model is sent")
        q = "Which identities are compromised, and what did I rule out?"
        chat_sent, err = captured_model_input(cid, q)
        check("chat reached the model", q in chat_sent, err)
        check("… with the Timeline verdicts", fb["title"] in chat_sent)
        check("… with the person marked compromised", "analyst_identity_verdicts" in chat_sent and pp["name"] in chat_sent)
        check("… with the manual event", manual_title in chat_sent)

        section("7. Chat can triage: a disposition by conversation")
        tgt = next(r for r in timeline(cid) if r.get("source") == "fusion" and r.get("validation", "pending") == "pending"
                   and r.get("host") and r["finding_id"] not in (fa["finding_id"], fb["finding_id"]))
        say = (f"The {det_name(tgt['title'])} on {tgt['host'].split(',')[0].strip()} is our IT admin's "
               "scheduled maintenance job — it is benign.")
        _sent, err = captured_model_input(cid, say)
        pend = (store.get_case(cid) or {}).get("pending_disposition")
        check("chat offers to mark it benign (and waits)", bool(pend), err or "no pending offer")
        if pend:
            _s, err = captured_model_input(cid, "confirm")
            disp = (store.get_case(cid) or {}).get("dispositions") or []
            check("'confirm' records the disposition", any(x.get("target") == pend.get("target") for x in disp), err)
            md2 = report_md(cid)
            check("the report reflects the chat disposition", "Known" in md2 or "False Positive" in md2)

        section("8. Exclude a host (Configuration)")
        call("POST", f"/api/cases/{cid}/config", {"excluded_hosts": [hx]})
        call("POST", f"/api/cases/{cid}/fuse")
        check("Risk drops the excluded host", hx not in [r["host"] for r in risk(cid)])
        check("Timeline drops it", not any(hx in [h.strip() for h in (r.get("host") or "").split(",")]
                                           for r in timeline(cid) if r.get("source") == "fusion"))
        check("Identities drop it", not any(hx in (p.get("seen_on") or []) for p in people(cid)))
        md3 = report_md(cid)
        check("the report drops it", f"| {hx} " not in md3 and f"**{hx}**" not in md3)
        sent3, _ = captured_model_input(cid)
        # Only the host AS A HOST: another machine's evidence may still mention it
        # (a BITS download from http://ALMECM01.corp…) — that is the other host's data.
        import re as _re
        as_host = _re.findall(r"(?<![/\\.\w])" + _re.escape(hx) + r"(?![.\w])", sent3)
        check("the model is not sent it as a host", not as_host, f"{len(as_host)} mention(s)")
        check("verdicts survive the re-fusion", pp["name"] in md3 and fb["title"] in md3)

        if LLM:
            section("9. Real model (soft checks: wording varies)")
            ans = call("POST", f"/api/cases/{cid}/chat", {"question": "Who did I mark as compromised, and which finding did I mark as a false positive?"}).get("answer") or ""
            soft("chat answer names the compromised person", pp["name"].lower() in ans.lower(), ans[:200])
            call("POST", f"/api/cases/{cid}/report", {"use_llm": True})
            for _ in range(180):
                time.sleep(10)
                c = call("GET", f"/api/cases/{cid}")
                if not c.get("report_generating"):
                    break
            rmd = call("GET", f"/api/cases/{cid}/report").get("report_md") or ""
            soft("real report written", len(rmd) > 1000, f"{len(rmd)} chars")
            soft("real report names the compromised person", pp["name"] in rmd)
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        check("the run completed", False, "exception above")
    finally:
        section("cleanup")
        ws.update_run_status(cid, "pending", details={"member_run_ids": []})
        res = call("DELETE", f"/api/cases/{cid}")
        check("throwaway case deleted", res.get("deleted") is True, str(res)[:200])
        check("the source case's run still exists", all(get_workflow(r) for r in runs))
        check("the source case is unchanged", len(timeline(SRC)) == src_rows)

    bad = [r for r in RESULTS if r[0] == "FAIL"]
    warn = [r for r in RESULTS if r[0] == "WARN"]
    print(f"\n{len(RESULTS) - len(bad) - len(warn)} ok, {len(bad)} failed, {len(warn)} warnings")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
