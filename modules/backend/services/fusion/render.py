"""Render the case graph at three altitudes (macro / infrastructural attack
timeline / per-asset) and produce the compact distilled payload. All
DETERMINISTIC — the graph already holds the findings + timestamps, so this
is templating, not analysis. The LLM (real or simulated) only narrates over
``distilled()``.
"""

from __future__ import annotations

from . import severity as sev, keys
from .correlate import in_window, _assets_of, _host_label


def fmt_ts(v) -> str:
    """One display format for every timestamp: 'YYYY-MM-DDTHH:MM:SSZ' (second
    precision, trailing Z). Strips fractional/nanosecond tails so the timeline
    reads uniformly regardless of which artifact produced the row."""
    t = keys.norm_ts(v)            # -> 'YYYY-MM-DDTHH:MM:SS' (or None)
    return (t + "Z") if t else ""


def scope(graph, *, window=None, min_severity="informational"):
    """Return (assets, findings) filtered to the time window + severity."""
    findings = [f for f in graph.findings
                if sev.at_least(f.severity, min_severity) and in_window(f.ts, window)]
    assets = [e for e in graph.by_type("asset")]
    return assets, findings


def _artifacts_of(graph, f) -> list:
    """The collection artifact(s) that produced a finding — so the analyst can ask
    the IT team 'do you recognise what <artifact> flagged at <time>?'. Derived from
    the finding's (and its cited entities') evidence locators, which look like
    'Windows.Hayabusa.Rules/row=5'. Falls back to the source module label."""
    arts = []
    seen = set()

    def add_from(evlist):
        for ev in (evlist or []):
            loc = getattr(ev, "locator", "") or ""
            name = loc.split("/row=")[0].split("/")[0].strip()
            if name and name not in ("asset", "") and name not in seen:
                seen.add(name)
                arts.append(name)

    add_from(getattr(f, "evidence", None))
    if not arts:
        for eid in (f.entity_ids or []):
            e = graph.entities.get(eid)
            if e:
                add_from(getattr(e, "evidence", None))
    if not arts and f.sources:
        arts = list(dict.fromkeys(f.sources))
    return arts


def timeline(graph, *, window=None, initial_access=None):
    rows = []
    for f in graph.findings:
        if not in_window(f.ts, window):
            continue
        rows.append({"finding_id": f.id,            # stable key for real/not-real validation
                     "ts": fmt_ts(f.ts), "host": ", ".join(_host_label(graph, a) for a in f.asset_ids) or "-",
                     "phase": _phase(f), "title": f.title, "severity": f.severity,
                     "mitre": f.mitre, "artifacts": _artifacts_of(graph, f),
                     "source": "fusion"})
    rows.sort(key=lambda r: (r["ts"] or "9999"))
    return rows


_PHASES = ["Initial Access", "Execution / Injection", "Persistence",
           "Command & Control", "Lateral Movement", "Exposure"]


def _phase(f) -> str:
    t, m = f.title.lower(), set(f.mitre)
    if "inject" in t or "T1055" in m:
        return "Execution / Injection"
    if "account" in t or {"T1021", "T1078"} & m:
        return "Lateral Movement"
    if "indicator" in t or "T1071" in m or "c2" in t:
        return "Command & Control"
    if t.startswith("vulnerability"):
        return "Exposure"
    if "persist" in t or "service" in t or "autorun" in t or "scheduled" in t:
        return "Persistence"
    return "Execution / Injection"


# ---- report_detail: per-case explicitness control --------------------------
# Auto resolves to EXPLICIT (per-event evidence: real cmdline / path / user / full
# hash) for small, specific cases and SUMMARY (abstracted findings only) for big /
# cross-org cases. EXPLICIT_MAX_HOSTS mirrors correlate.FLEET_RELATIVE_MIN (the
# fleet-relative threshold) — below it a case is "specific", above it "at scale".
# At macro altitude the flat timeline was ~half the whole report, mostly the same
# detection repeating. Collapse to recurring groups and cap them; the count + span
# preserve the information a raw repeat list carried.
TIMELINE_MAX_GROUPS = 40
# Below this share of findings carrying an ATT&CK technique, a technique matrix
# implies coverage the data does not have — state the coverage instead.
MITRE_MIN_COVERAGE_PCT = 25
# Host table at scale: show the hosts that matter, count the rest.
RISK_TABLE_MAX_ROWS = 15

EXPLICIT_MAX_HOSTS = 12
EXPLICIT_MAX_FINDINGS = 150
EXPLICIT_EVENTS_PER_FINDING = 6            # evidence lines surfaced per finding
# Per evidence line in the LLM payload. 200 truncated the one thing the deep/focused
# view exists to show: the exact command line and the full -EncodedCommand blob (so the
# base64 could not be decoded past its prefix). Applies ONLY to explicit detail
# (focused/narrow cases), so macro summary payloads are unaffected; the budget
# stepdown still bounds the total if a narrow case turns out large.
EXPLICIT_EVIDENCE_CHARS = 32000           # per evidence line, LLM payload — full cmd + full -EncodedCommand (so it decodes completely)
# The SAME evidence, rendered for a human, gets far more room. 200 characters is
# a budget number: it exists because every one of these lines is also sent to the
# model, where five per finding across 150 findings is real money. The report is
# not on that budget, and truncating there was costing the operator the end of
# every Defender message -- the threat name, the URL, the path -- with an ellipsis
# baked into the markdown, so the Markdown and PDF exports carried the cut too.
#
# Still capped, because a single base64 PowerShell blob can run to tens of
# kilobytes and would swamp both the page and the PDF.
REPORT_EVIDENCE_CHARS = 32000   # deterministic timeline: full command / full encoded blob, not cut


def _resolve_detail(graph, detail, *, window=None, min_severity="informational"):
    """Resolve the per-case ``report_detail`` control to (effective_mode, reason).
    'explicit'/'summary' are honored verbatim; 'auto' picks explicit when the case
    is small AND specific (few hosts AND bounded finding volume), else summary."""
    d = (detail or "auto").lower()
    if d not in ("auto", "explicit", "summary"):
        d = "auto"
    if d != "auto":
        # The reason must SAY SOMETHING. Returning `d` twice rendered the footer as
        # "Report detail: **explicit** (explicit)", which tells the analyst nothing
        # about why the report is as deep as it is.
        return d, "set for this case"
    hosts = len(graph.by_type("asset"))
    _, findings = scope(graph, window=window, min_severity=min_severity)
    nf = len(findings)
    if hosts <= EXPLICIT_MAX_HOSTS and nf <= EXPLICIT_MAX_FINDINGS:
        return "explicit", f"auto — {hosts} host{'' if hosts == 1 else 's'}, {nf} findings"
    return "summary", f"auto — {hosts} hosts, {nf} findings (at scale)"


# ---- report altitude: macro (triage map) vs focused (one explicit theory) ------
# A case with SEVERAL SUBSTANTIAL ACTIVITY WINDOWS ACROSS SEVERAL HOSTS reads as
# candidate scenarios to triage between, NOT one intrusion story — forcing one story
# there over-commits and bloats. Anything narrower wants a single explicit theory in
# depth. Validated in scratch_eval/: the macro prompt beats a forced single story
# 24-25 vs 13-14 at every broad scope (3->100 hosts), and the tightened focused
# prompt beats the verbose baseline 20 vs 17 on a narrow case, at 3.4-4.5x lower
# output cost throughout.
#
# SPAN IS NOT A TRIGGER, and used to be. It is driven by the OLDEST ARTIFACT
# TIMESTAMP in the data — a two-year-old registry or file time — not by how long the
# incident lasted, so it made macro reports out of cases with nothing to map: test5
# (one host, 31 findings) came back segmented and empty because its evidence happened
# to reach back 120 days. Substantial windows and host count are what actually say
# whether there is more than one story here.
MACRO_SPAN_DAYS = 90
# How many activity windows a macro report MAPS. One list feeds the zoom cards, the
# deterministic timeframe table AND the model's per-timeframe sections, so all three
# agree by construction. The cards used to take 4 and the table 6, so rows 5-6 of the
# table had no card to click.
MACRO_TIMEFRAMES = 6
# A phase carrying more than this is not a phase, it is a second case: split it at
# its widest internal seam. Measured on a live 757-day case, the 7-day gap rule
# produced one window of 78 findings over 75 days (half the case) next to one of 2.
SPLIT_MAX_FINDINGS = 25
SPLIT_MAX_SPAN_DAYS = 21
SPLIT_MIN_KEEP = 2
# A seam must stand out against the group's own rhythm, or it is not a seam.
SPLIT_SEAM_RATIO = 3.0
SPLIT_MIN_SEAM_SECONDS = 2 * 24 * 3600
# ACTIVITY mode clusters on when a behaviour is FIRST seen, so a wider gap is right:
# it is spacing between *new* techniques appearing, not between every repeat.
ACTIVITY_GAP_DAYS = 14
# A window is worth a section of its own -- and counts toward "this case has distinct
# phases" -- only when it holds real material: a few findings, or anything high or
# above. Two single-medium blips ten days apart are not a campaign map.
MIN_SUBSTANTIAL_FINDINGS = 3


def _evidence_span_days(findings) -> int:
    ts = [f.ts for f in findings if f.ts]
    if not ts:
        return 0
    lo, hi = keys.to_utc_dt(min(ts)), keys.to_utc_dt(max(ts))
    return (hi - lo).days if (lo and hi) else 0


def _title_normaliser(graph):
    """`SIGMA: X on ALDC02` -> `SIGMA: X`, so the same detection across hosts is ONE
    activity. The same rule the timeline collapse uses; hoisted here because the
    activity grouping needs it too."""
    labels = {a.label for a in graph.by_type("asset") if a.label}

    def norm(t):
        for lb in labels:
            if (t or "").endswith(f" on {lb}"):
                return t[: -(len(lb) + 4)]
        return t or ""
    return norm


def _split_oversized(cl):
    """Recursively cut a cluster at its WIDEST internal gap until each part is a
    plausible phase. The widest gap is the most natural seam the data offers -- far
    better than a second fixed threshold, which just moves the arbitrariness."""
    span = (cl[-1][0] - cl[0][0]).days
    if len(cl) <= SPLIT_MAX_FINDINGS and span <= SPLIT_MAX_SPAN_DAYS:
        return [cl]
    if len(cl) < 2 * SPLIT_MIN_KEEP:
        return [cl]
    gaps = [((cl[i + 1][0] - cl[i][0]).total_seconds(), i)
            for i in range(SPLIT_MIN_KEEP - 1, len(cl) - SPLIT_MIN_KEEP)]
    if not gaps:
        return [cl]
    widest, i = max(gaps)
    # ONLY SPLIT AT A REAL SEAM. On evenly-spaced activity -- a steady drip, one
    # finding every few days for months -- every gap is the same size, so "cut at
    # the widest" cuts at nothing: it just relocates the arbitrariness it was meant
    # to remove. That IS one continuous phase and must stay one. Require the seam
    # to stand out against the group's own rhythm before believing in it.
    allg = sorted(g for g, _ in gaps)
    median = allg[len(allg) // 2]
    if widest < max(SPLIT_MIN_SEAM_SECONDS, median * SPLIT_SEAM_RATIO):
        return [cl]
    return _split_oversized(cl[:i + 1]) + _split_oversized(cl[i + 1:])


def zoom_targets(graph, *, window=None, min_severity="informational",
                 n=MACRO_TIMEFRAMES, gap_days=7, mode="time"):
    """Deterministic phases of the case: contiguous groups of findings, each a
    {hosts, window} the operator can one-click re-scope to. No LLM — grounded
    straight from the finding timestamps, so the scope is always real.

    TWO GROUPINGS, same output shape, so the report, the cards, the table and the
    payload are untouched by the choice:

      mode="time"     — split wherever findings go quiet for `gap_days`, then split
                        any oversized result at its widest internal seam.
      mode="activity" — split on when a behaviour is FIRST seen. Later hits of the
                        same detection are that behaviour PERSISTING, not a new
                        event, so they no longer start a window of their own.

    Why the second mode exists: measured on a live 757-day case, 148 findings were
    only 63 distinct activities, and 32 recurring ones carried 114 of them (77%).
    Time-gap splitting scattered `Suspicious Service Path` -- 8 hits over 413 days
    across 8 hosts -- through six separate windows, so no window held anything
    coherent and none could be described. Grouping on first appearance instead
    yields phases that mean "new tooling entered the environment here".
    """
    _, findings = scope(graph, window=window, min_severity=min_severity)
    dated = []
    for f in findings:
        t = keys.to_utc_dt(f.ts) if f.ts else None
        if t is not None:
            dated.append((t, f))
    dated.sort(key=lambda x: x[0])

    if mode == "activity":
        # Cluster the FIRST sighting of each distinct activity; every later hit of
        # that activity is carried along with its own group.
        norm = _title_normaliser(graph)
        acts = {}
        for t, f in dated:
            acts.setdefault(norm(f.title), []).append((t, f))
        firsts = sorted(((v[0][0], k) for k, v in acts.items()), key=lambda r: r[0])
        buckets, cur, last = [], [], None
        for t, key in firsts:
            if last is not None and (t - last).days > ACTIVITY_GAP_DAYS and cur:
                buckets.append(cur); cur = []
            cur.append((t, key)); last = t
        if cur:
            buckets.append(cur)
        # A PHASE IS THE MOMENT OF APPEARANCE, not the whole life of what appeared.
        # Carrying every later recurrence into its phase made phase 1 span fourteen
        # months and swallow phases that started inside it -- overlapping windows,
        # which breaks "click this window to zoom" outright. Keep only the hits
        # inside the appearance period; the recurrences are stated once in
        # the "Activity outside the analysed phases" timeline, which is where
        # everything no phase covers is accounted for.
        clusters = []
        for b in buckets:
            lo, hi = b[0][0], b[-1][0]
            hits = [(t, f) for _, key in b for (t, f) in acts[key] if lo <= t <= hi]
            if hits:
                clusters.append(sorted(hits, key=lambda x: x[0]))
    else:
        clusters, cur, last = [], [], None
        for t, f in dated:
            if last is not None and (t - last).days > gap_days and cur:
                clusters.append(cur); cur = []
            cur.append((t, f)); last = t
        if cur:
            clusters.append(cur)
        # One 78-finding / 75-day window next to one of 2 findings is not a map.
        clusters = [part for cl in clusters for part in _split_oversized(cl)]

    out = []
    for cl in clusters:
        fs = [f for _, f in cl]
        times = [t for t, _ in cl]
        hosts = {}
        for f in fs:
            for a in (f.asset_ids or []):
                hosts[a] = _host_label(graph, a)
        if not hosts:
            continue
        top_sev = max((f.severity for f in fs), key=lambda s: sev.rank(s))
        cross = sum(1 for f in fs if f.kind == "cross_host")
        mitre = sorted({m for f in fs for m in (f.mitre or [])})[:6]
        lo, hi = min(times), max(times)
        # pad the window by an hour each side so boundary events aren't clipped
        import datetime as _dt
        start = (lo - _dt.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S")
        end = (hi + _dt.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S")
        labels = sorted(set(hosts.values()))
        span_h = round((hi - lo).total_seconds() / 3600, 1)
        # The distinct detections inside this window, highest severity first, with
        # the "on <host>" tail stripped so one rule across hosts is one title. This
        # is what the model narrates a window FROM: it gets the window as a fixed,
        # numbered anchor plus what is in it, and can describe but never invent one.
        def _bare(t):
            for h in labels:
                if t.endswith(f" on {h}"):
                    return t[: -(len(h) + 4)]
            return t
        seen_t, titles = set(), []
        for f in sorted(fs, key=lambda x: -sev.rank(x.severity)):
            t = _bare(f.title or "")
            if t and t not in seen_t:
                seen_t.add(t); titles.append(t)
            if len(titles) >= 10:
                break
        title = (f"{lo.strftime('%Y-%m-%d')} — {len(labels)} host"
                 f"{'' if len(labels) == 1 else 's'}, {len(fs)} finding"
                 f"{'' if len(fs) == 1 else 's'}"
                 + (f", {top_sev}" if top_sev not in ("informational",) else ""))
        out.append({
            "title": title, "severity": top_sev, "finding_count": len(fs),
            "cross_host": cross, "mitre": mitre,
            "hosts": sorted(hosts.keys()), "host_labels": labels,
            "window": {"start": start, "end": end}, "span_hours": span_h,
            "top_titles": titles,
            "critical_count": sum(1 for f in fs if f.severity == "critical"),
            # Rank on what DISCRIMINATES. `severity` is the max in the group, so on a
            # real case every group reads "critical" off a handful of criticals and
            # the column sorts nothing -- measured: all six windows identical. The
            # count of criticals, the cross-host links and the host spread do vary.
            "_risk": (sum(1 for f in fs if f.severity == "critical") * 1000
                      + cross * 100 + len(labels) * 25 + len(fs)),
        })
    out.sort(key=lambda z: -z["_risk"])
    for z in out:
        z.pop("_risk", None)
    # COVERAGE. The tail used to be truncated away: 17 clusters existed and 6 were
    # shown, so 11 windows of evidence appeared in no window, no table and no
    # section -- invisible rather than deprioritised. Report the remainder as one
    # explicit rollup so every finding is accounted for somewhere.
    rest = out[n:]
    out = out[:n]
    if rest:
        rf = sum(z["finding_count"] for z in rest)
        rc = sum(z.get("critical_count", 0) for z in rest)
        rh = sorted({h for z in rest for h in (z.get("host_labels") or [])})
        rest.sort(key=lambda z: z["window"]["start"])
        lo = min(z["window"]["start"] for z in rest)
        hi = max(z["window"]["end"] for z in rest)
        out.append({"title": f"{len(rest)} further window(s) — {rf} finding(s)",
                    "severity": max((z["severity"] for z in rest),
                                    key=lambda x: sev.rank(x)),
                    "finding_count": rf, "critical_count": rc, "cross_host": 0,
                    "mitre": [], "hosts": [], "host_labels": rh,
                    "window": {"start": lo, "end": hi}, "span_hours": 0.0,
                    "top_titles": [], "rollup": True, "rollup_windows": len(rest)})
    # Numbered AFTER ranking and truncation: "Timeframe 3" means the same window on
    # the card, in the table and in the narrative, or the analyst zooms into the
    # wrong one.
    i = 0
    for z in out:
        if z.get("rollup"):
            continue          # an accounting row, not a zoomable phase -- no number
        i += 1
        z["n"] = i
    return out


def _substantial(z) -> bool:
    """Is this window worth a section of its own?

    Volume, or a CRITICAL. It used to be volume or "anything high or above", and
    on a real case that is no filter at all: high IS the norm -- 134 of 148
    findings on one live case -- so every single finding qualified as its own
    phase. Measured consequence: a 1-host, 31-finding case whose evidence happened
    to span 400 days was segmented into SIX phases of ONE finding each, instead of
    one focused narrative over the whole thing. That is the "small scope is very
    underwhelming" report.

    A lone critical still earns a section (criticals are rare -- 9 of 148 there --
    so it is a real signal); a lone high does not.
    """
    return (z.get("finding_count", 0) >= MIN_SUBSTANTIAL_FINDINGS
            or z.get("critical_count", 0) >= 1)


def analysable(zt):
    """The phases worth an analyst's time -- what the model narrates and what the
    console offers as a clickable scope.

    Excludes two things. The coverage rollup is a tally of what was NOT reported in
    its own right; it has no story to tell and must not be handed to the model as if
    it did. And a window below _substantial() is not a scope: measured on a narrowed
    graph, four of six offered cards were a SINGLE finding each, so "Analyze this
    scope" led almost nowhere. Both still have every finding accounted for in the
    rollup and in the timeline.

    Deliberately NOT applied inside zoom_targets(): that is the primitive the
    altitude rule counts substantial windows from, and filtering there would make it
    count its own filtered output -- which broke both the altitude and the
    cluster-splitting tests.
    """
    return [z for z in zt if not z.get("rollup") and _substantial(z)]


def phases_at_a_glance_md(zt, names=None) -> str:
    """Every phase on one screen, so the reader can choose before reading any of them.

    Deterministic: the counts, hosts and windows are ours. The NAME column is the
    model's label for the phase when the report carried one -- the whole value of the
    table is being able to compare "what each phase IS" side by side, which a window
    and a count cannot express.
    """
    rows = analysable(zt)
    if not rows:
        return ""
    names = names or {}
    out = ["## Phases at a glance", "",
           "_Every phase, ranked by risk. The window and counts are deterministic; "
           "open a phase below, or one-click **Analyze this scope** in the console to "
           "re-scope the case to it._", "",
           "| # | Phase | Window (UTC) | Hosts | Findings | Crit | ATT&CK |",
           "|---|---|---|---|---|---|---|"]
    for z in rows:
        w, hs = z["window"], (z.get("host_labels") or [])
        hosts = ", ".join(hs[:4]) + ("…" if len(hs) > 4 else "")
        nm = names.get(z["n"]) or (z.get("top_titles") or ["—"])[0][:48]
        mitre = ", ".join((z.get("mitre") or [])[:4]) or "—"
        out.append(f"| {z['n']} | {nm} | {w['start'][:16]} → {w['end'][:16]} | "
                   f"{hosts} | {z['finding_count']} | {z.get('critical_count', 0)} | "
                   f"{mitre} |")
    roll = [z for z in zt if z.get("rollup")]
    if roll:
        r = roll[0]
        out.append(f"| — | _{r['rollup_windows']} further window(s), not analysed "
                   f"individually_ | {r['window']['start'][:16]} → "
                   f"{r['window']['end'][:16]} | | {r['finding_count']} | "
                   f"{r.get('critical_count', 0)} | — |")
    return "\n".join(out) + "\n"


def report_mode_banner(altitude, zt, *, mode="time", total_findings=None) -> str:
    """Say WHICH report this is, at the top, in the operator's words.

    Asked for directly: "we do need to know if its macro or segmented report".
    A segmented report covering six phases and a focused report on one scope read
    completely differently, and nothing distinguished them.
    """
    if altitude != "macro":
        return ("_**Focused report** — one scope, analysed in depth. "
                "Every finding below is inside this window._")
    phases = len(analysable(zt))
    roll = [z for z in zt if z.get("rollup")]
    extra = (f" A further {roll[0]['rollup_windows']} window(s) covering "
             f"{roll[0]['finding_count']} finding(s) are summarised in the phase "
             f"table but not analysed individually." if roll else "")
    grouped = ("grouped by when a behaviour FIRST appeared" if mode == "activity"
               else "grouped by periods of continuous activity")
    # ACTIVITY mode deliberately leaves later recurrences OUT of the phases -- a
    # phase is the moment something appeared. Those findings are not lost, they are
    # in "Activity outside the analysed phases", but the banner must say so instead
    # of implying the phases account for everything.
    if total_findings:
        inphase = sum(z["finding_count"] for z in zt)
        rec = total_findings - inphase
        if rec > 0:
            extra += (f" {rec} further finding(s) are later repeats of behaviours that "
                      f"first appeared in these phases — see **Activity outside the "
                      f"analysed phases**.")
    return (f"_**Segmented report** — broad scope, split into {phases} phase(s) "
            f"{grouped}. Each phase below is analysed on its own and carries its own "
            f"timeline; open one to go deeper.{extra}_")


def outside_phases(graph, zt, *, window=None, min_severity="informational"):
    """The in-scope findings that NO analysed phase covers.

    Measured on a live case: 61 findings across 15 windows fell into the coverage
    rollup, appearing as table rows and timeline bullets with no prose anywhere --
    40% of the case, including renamed-tool drops (AdFind, procdump, procdump64).
    The macro prompt used to carry an "Other severe findings" section for exactly
    this, noting that scenarios alone covered 95% of critical findings but only 57%
    of high ones. This is the set that section needs.
    """
    _, findings = scope(graph, window=window, min_severity=min_severity)
    wins = [(z["window"]["start"], z["window"]["end"]) for z in analysable(zt)]
    out = []
    for f in findings:
        ts = f.ts or ""
        if not any(lo <= ts <= hi for lo, hi in wins):
            out.append(f)
    return out


def outside_phases_digest(graph, findings, limit=40):
    """Compact {title, severity, hosts, ts} rows for the synthesis payload -- enough
    to group and name them, without re-sending evidence the phases already carry."""
    norm = _title_normaliser(graph)
    seen, rows = {}, []
    for f in sorted(findings, key=lambda x: -sev.rank(x.severity)):
        if not sev.at_least(f.severity, "high"):
            continue
        t = norm(f.title)
        if t in seen:
            seen[t]["count"] += 1
            continue
        seen[t] = {"title": t, "severity": f.severity, "count": 1,
                   "hosts": sorted({_host_label(graph, a) for a in (f.asset_ids or [])}),
                   "first": f.ts}
        rows.append(seen[t])
        if len(rows) >= limit:
            break
    return rows


def timeframes_for_payload(zt):
    """The fixed, numbered anchors the macro model narrates from. Compact on purpose:
    the findings themselves are already in the payload; this is the index that says
    which of them belong to which window."""
    return [{"n": z["n"], "window": z["window"], "hosts": z.get("host_labels") or [],
             "critical_count": z.get("critical_count", 0),
             "finding_count": z["finding_count"], "cross_host": z.get("cross_host", 0),
             "severity": z["severity"], "mitre": z.get("mitre") or [],
             "findings": z.get("top_titles") or []} for z in analysable(zt)]


def suspicious_timeframes_md(graph, *, window=None, min_severity="informational",
                             n=MACRO_TIMEFRAMES, zt=None):
    """Deterministic 'Suspicious Timeframes & Clusters' heat-map for a macro report,
    rendered from zoom_targets — so it is ALWAYS accurate and matches the clickable
    zoom cards exactly (the LLM no longer writes this section; feeding it the clusters
    made it confabulate — see scratch_eval S4). Returns '' for a focused case."""
    if zt is None:
        zt = zoom_targets(graph, window=window, min_severity=min_severity, n=n)
    if not zt:
        return ""
    rows = ["## Suspicious Timeframes & Clusters", "",
            "_The ranked activity hotspots (deterministic). Each is a one-click "
            "**Analyze this scope** zoom in the console._", "",
            "| # | Window (UTC) | Hosts | Findings | Severity | ATT&CK |",
            "|---|---|---|---|---|---|"]
    for i, z in enumerate(zt, 1):
        i = z.get("n", i)
        w = z["window"]
        labels = z.get("host_labels") or []
        hosts = ", ".join(labels[:6]) + ("…" if len(labels) > 6 else "")
        mitre = ", ".join((z.get("mitre") or [])[:4]) or "—"
        ch = f" ({z['cross_host']} cross-host)" if z.get("cross_host") else ""
        rows.append(f"| {i} | {w['start']} → {w['end']} | {hosts} | "
                    f"{z['finding_count']}{ch} | {z['severity']} | {mitre} |")
    return "\n".join(rows) + "\n"


import re as _tf_re
# "Phase" is what the segmented report writes; "Timeframe" is kept so a report
# generated before the rename still yields its names instead of blank cards.
_TF_HEADING = _tf_re.compile(
    r"^###\s*(?:Phase|Timeframe)\s+(\d+)\s*[—–\-:]\s*(.+?)\s*$", _tf_re.M)


def timeframe_names_from_report(md) -> dict:
    """{n: name} for every `### Timeframe N — name` heading the model wrote. The
    zoom cards use it so a card says what its window IS, not just when it was."""
    return {int(n): name.strip().strip("*").strip()
            for n, name in _TF_HEADING.findall(md or "")}


def merge_timeframes_section(narrative, table_md, valid_ns):
    """Put the deterministic timeframe table under the model's `## Timeframes`
    heading, and drop any `### Timeframe N` block whose N is not a real window.

    The windows are OURS (zoom_targets); only the words are the model's. Feeding a
    model the clusters and letting it write the table made it confabulate dates
    (scratch_eval S4), which is why the table stayed deterministic. Numbered
    anchors let it narrate each window without owning the facts -- and a number
    that matches nothing is exactly the confabulation this guards against.

    Returns (markdown, dropped_numbers, table_was_inserted)."""
    lines = (narrative or "").split("\n")
    kept, dropped, skipping = [], [], False
    for ln in lines:
        m = _TF_HEADING.match(ln)
        if m:
            n = int(m.group(1))
            if n not in valid_ns:
                skipping = True; dropped.append(n); continue
            skipping = False
        elif ln.startswith("## ") or ln.startswith("### "):
            skipping = False
        if not skipping:
            kept.append(ln)
    md = "\n".join(kept)
    inserted = False
    if table_md:
        h = _tf_re.search(r"^##\s*Timeframes\s*$", md, _tf_re.M)
        if h:
            body = table_md.split("\n", 1)[1] if table_md.startswith("## ") else table_md
            md = md[:h.end()] + "\n\n" + body.strip("\n") + "\n" + md[h.end():]
            inserted = True
    return md, dropped, inserted


def _resolve_altitude(graph, *, window=None, min_severity="informational"):
    """(altitude, reason): 'macro' when the scope is broad by hosts, finding volume,
    OR evidence span; else 'focused'. Reuses the report_detail thresholds."""
    assets, findings = scope(graph, window=window, min_severity=min_severity)
    # Count hosts that are actually IN SCOPE — i.e. that carry a finding inside the
    # window/severity filter — not every asset in the graph. scope() deliberately
    # returns ALL assets (they anchor the graph and must never be filtered out of the
    # report), but using that count here made the altitude ignore narrowing entirely:
    # measured on a 30-host case, narrowing to a 3-day window cut findings 1081 -> 25
    # and the span 199d -> 3d, yet it stayed MACRO because the host count never moved.
    # On any fleet above the host threshold, time-narrowing could therefore NEVER reach
    # a focused report — which is exactly what the zoom loop promises the analyst.
    in_scope = {a for f in findings for a in (f.asset_ids or [])}
    hosts = len(in_scope) if findings else len(assets)
    nf = len(findings)
    span = _evidence_span_days(findings)
    # The SHAPE of the activity in time, not just its length. A macro report is a
    # map of distinct phases; it is the right altitude when there ARE distinct
    # phases. Span alone got this wrong in both directions: a two-year case whose
    # findings form one continuous cluster was forced to macro (nothing to map, and
    # the operator had to override to explicit by hand), while two real phases 60
    # days apart stayed focused because 60 < 90. Clustering answers the actual
    # question -- and it is the same clustering the zoom cards use, so narrowing to
    # any one window yields one cluster and drops to focused: the loop closes.
    zt = zoom_targets(graph, window=window, min_severity=min_severity)
    windows = len(zt)
    substantial = sum(1 for z in zt if _substantial(z))
    reason = (f"{hosts} hosts, {nf} findings, {windows} activity window(s) "
              f"({substantial} substantial), {span}d span")
    if hosts > EXPLICIT_MAX_HOSTS or nf > EXPLICIT_MAX_FINDINGS:
        return "macro", reason                      # too big to narrate explicitly
    # ONE MACHINE IS ONE STORY. Segmentation exists because a case is too much to
    # read as a single narrative and the analyst must triage BETWEEN episodes --
    # which needs more than one host. A single host split into phases is the
    # focused report's step-by-step reconstruction, done worse: measured on a live
    # 1-host / 31-finding case, it produced three phases of 21/5/3 findings where
    # one explicit narrative was plainly the better document. Volume alone still
    # forces macro through the rule above.
    if substantial >= 2 and hosts > 1:
        return "macro", reason                      # distinct phases: map them
    # NO SPAN-ONLY CLAUSE. There used to be one -- "windows >= 2 and span > 90:
    # sparse but long, still a map" -- and it segmented cases that had nothing to
    # map. A 1-host, 31-finding case whose evidence happened to stretch 400 days
    # tripped it with seven windows of which ONE was substantial, and was split
    # into six one-finding sections instead of getting a single focused narrative.
    #
    # Span is the wrong signal on its own and has now been wrong twice: it is
    # driven by the oldest artifact timestamp in the data -- a two-year-old
    # registry or file time -- not by how long the incident lasted. Whether there
    # are DISTINCT PHASES worth mapping is the actual question, and `substantial`
    # above answers it.
    return "focused", reason


def _hash_name_map(graph):
    """{full_hash: filename} from the ioc entities' source_name (captured at fuse time).
    Cached on the graph so per-finding evidence lookups are O(1). Lets the narrative
    pair a hash with the file it came from -- generic, works for any/unknown binary."""
    m = getattr(graph, "_hash_name_cache", None)
    if m is None:
        m = {}
        for e in graph.entities.values():
            if e.type == "ioc" and (e.attrs or {}).get("ioc_kind") == "hash":
                sn = (e.attrs or {}).get("source_name")
                fh = (e.attrs or {}).get("full_hash") or e.label
                if sn and fh:
                    m[str(fh).lower()] = str(sn).replace("\\", "/").rsplit("/", 1)[-1]
        try:
            graph._hash_name_cache = m
        except Exception:
            pass
    return m


def _finding_evidence(graph, f, *, cap_events=EXPLICIT_EVENTS_PER_FINDING,
                      cap_chars=EXPLICIT_EVIDENCE_CHARS) -> list:
    """Per-event explicit evidence for a finding — the real cmdline / path / user /
    target IP / full hash captured on its linked event entities (EXPLICIT mode only;
    the lossy ontology drops these from the summary view). Capped for budget safety."""
    def _v(x):                              # usable value, or "" for noise/placeholders
        x = ("" if x is None else str(x)).strip()
        return "" if x.lower() in ("", "unknown", "-", "n/a", "none") else x

    lines = []
    for eid in (f.entity_ids or []):
        e = graph.entities.get(eid)
        if not e or e.type != "event":
            continue
        a = e.attrs or {}
        parts = []
        if _v(a.get("ev_user")):
            parts.append(f"user={_v(a.get('ev_user'))}")
        has_proc = False
        if _v(a.get("ev_cmdline")):
            parts.append(f"cmd: {_v(a.get('ev_cmdline'))}")
            has_proc = True
        elif _v(a.get("ev_proc")):
            parts.append(f"proc: {_v(a.get('ev_proc'))}")
            has_proc = True
        if _v(a.get("ev_tgtip")):
            parts.append(f"→ {_v(a.get('ev_tgtip'))}")
        if _v(a.get("ev_sha256")):
            parts.append(f"sha256={_v(a.get('ev_sha256'))}")
        # THE DESCRIPTION, when nothing else says what happened.
        #
        # This used to be `if not parts` — a pure fallback — which meant an
        # event that captured a user but no process rendered as the bare word
        # `user=Administrator` and threw its description away. Having MORE
        # information made the output strictly worse: the same class of event
        # (a cleared event log) read "The Application log file was cleared."
        # when no user was attached, and told the reader nothing when one was.
        #
        # Measured on a real case of 694 events: 27 lines looked like that.
        # Gated on has_proc rather than on `not parts` so the 341 lines that DO
        # name a command line or a process are untouched — whether those should
        # also carry their description is a density judgement, not this bug.
        detail_txt = _v(a.get("details"))
        if detail_txt and not has_proc:
            parts.append(detail_txt)
        if not parts:
            continue
        # Flatten to ONE clean line: raw details can carry newlines / tabs / backticks
        # (e.g. a multi-line Defender message + URL) which would break the markdown
        # inline-code span and corrupt the whole report. Collapse + neutralise.
        s = " · ".join(parts)
        s = " ".join(s.split()).replace("`", "'")
        if len(s) > cap_chars:
            s = s[:cap_chars - 1] + "…"
        if s and s not in lines:
            lines.append(s)
        if len(lines) >= cap_events:
            break
    return lines


def _known_identities(graph, limit=5000):
    # No practical cap: the whole point of this function is that a real person
    # is never dropped merely because their accounts carry no anomaly score.
    # `limit` exists only as a defensive ceiling against a pathological graph —
    # at ~100 bytes/identity even a genuinely huge case (hundreds of identities)
    # adds a rounding error to what this payload already carries.
    """Cross-host identity clusters (Identities tab data) as a compact summary.

    top_entities below is ranked by ANOMALY SCORE, so a person who is simply
    present on several hosts with no attached finding — anomaly=0 on every one
    of their per-host account records — never survives the truncation, however
    many entities the case has. That is a real gap: the Identities tab already
    knows this person exists and which hosts they operate (exact-username
    clustering across hosts), but the chat/report LLM had no access to that
    clustering at all and would flatly deny the person existed (reported
    2026-07-26 — asked about a real, 5-host identity named in the Identities
    tab; the model correctly said it wasn't in the evidence it was given,
    because it genuinely wasn't). Feed the same clustering in here so the two
    views of one case agree on who exists.
    """
    try:
        from .identities import resolve_identities
        idents = resolve_identities(graph)
    except Exception:
        return []
    # RANK BY WHAT MATTERS TO THE INVESTIGATION before any truncation.
    # resolve_identities() sorts for the Identities TAB — by infrastructure
    # breadth, then account count — which is right for browsing but wrong for a
    # budget cut: it would keep a quiet admin who happens to span 5 systems and
    # drop the person actually named in a critical finding. Re-rank here, for
    # the LLM payload only, so whatever survives a cut is the part that matters.
    acct_sev = {}                      # account entity id -> worst finding severity rank
    for f in graph.findings:
        r = sev.rank(f.severity)
        for eid in (f.entity_ids or []):
            if r > acct_sev.get(eid, -1):
                acct_sev[eid] = r

    def _risk(ident):
        ids = [a["id"] for a in ident["accounts"]]
        worst = max((acct_sev.get(i, -1) for i in ids), default=-1)
        n_findings = sum(1 for i in ids if i in acct_sev)
        return (worst, n_findings, len(ident["accounts"]))

    idents = sorted(idents, key=_risk, reverse=True)

    out = []
    for i in idents:
        # `i["hosts"]` is the OPERATES-hosts heuristic (hostname textually implies
        # this person administers it) — often empty, as it was for the person this
        # bug was found on. What "who is X" actually needs is where the account was
        # SEEN, which is each account's own ctx (the endpoint it was observed on).
        seen_on = sorted({a["ctx"] for a in i["accounts"] if a.get("ctx")})
        out.append({"name": i["name"], "accounts": len(i["accounts"]),
                    "seen_on_hosts": seen_on,
                    "operates_hosts": [h["label"] for h in i["hosts"]]})
    return out[:limit]


# Default identity ceiling when the case leaves 'Identity limit' empty.
# NOT tied to max_entities: identities cost ~27 tokens each (two orders of
# magnitude cheaper than an entity row) and answer a different question ("who
# exists here"), so binding them to an entity budget sized for a different kind
# of content silently dropped real people — chat's budget is 60 entities, so a
# 61st person became invisible to the very path where "who is X" is asked.
# The real overflow guard is distilled()'s budget_chars stepdown, which shrinks
# identities alongside entities when the payload genuinely doesn't fit.
DEFAULT_MAX_IDENTITIES = 500

# Floor for the finding stepdown. Even a hard budget squeeze leaves this many —
# below it the report has no material to narrate, and >= high findings are exempt
# from trimming anyway (_trim_findings), so this only bounds the low-severity tail.
_MIN_FINDINGS = 20


def _trim_findings(findings, max_findings):
    """Keep the highest-severity findings, dropping only the low-severity tail.

    `findings` arrives severity-sorted (correlate.assemble sorts by -severity,
    then ts), so the tail IS the least important. Anything >= high is exempt and
    survives regardless of the cap: a budget squeeze may cost the operator some
    medium/low noise, never a critical detection.
    """
    if not max_findings or len(findings) <= max_findings:
        return findings
    must_keep = [f for f in findings if sev.at_least(f.severity, "high")]
    tail = [f for f in findings if not sev.at_least(f.severity, "high")]
    room = max(0, max_findings - len(must_keep))
    return must_keep + tail[:room]


def _distilled_at(graph, *, window, min_severity, max_entities, detail="summary",
                  max_identities=None, max_findings=None, include_ids=False,
                  include_timeframes=False):
    """`max_findings` caps findings AND the timeline built from them (they are the
    same set — the timeline is one row per finding), keeping them consistent so
    the payload never cites a finding_id it did not send.

    `max_identities` (the case's 'Identity limit' setting) caps identity rows
    INDEPENDENTLY of max_entities — see DEFAULT_MAX_IDENTITIES for why. Unset =
    DEFAULT_MAX_IDENTITIES, which covers any realistic engagement (~1.5
    identities per host). Overflow is still bounded: distilled() shrinks this in
    lockstep with max_entities on each budget_chars stepdown."""
    assets, findings = scope(graph, window=window, min_severity=min_severity)
    # Count BEFORE trimming: `scope` describes the case, not the payload. Reporting
    # the trimmed count here told the model "300 hosts, 40 findings" for a case where
    # all 300 hosts had one -- implying most machines were clean. The tool layer had
    # the same defect and made the loop answer "15 hosts" for a 42-host incident.
    total_findings = len(findings)
    findings = _trim_findings(findings, max_findings)
    kept_ids = {f.id for f in findings}
    eff_detail, _ = _resolve_detail(graph, detail, window=window, min_severity=min_severity)
    in_scope_ents = [e for e in graph.entities.values()
                     if e.type != "asset" and sev.at_least(e.severity, min_severity)
                     and in_window(e.first_seen, window)]
    total_entities = len(in_scope_ents)
    ents = sorted(in_scope_ents, key=lambda e: -e.anomaly)[:max_entities]

    # Resolve identities ONCE without a cap, then trim: the true count is then free.
    # Budget stepdowns shrink this list, and the model counted the list it received
    # as the population -- answering "323 distinct user accounts" for a case with
    # 400, citing the truncated name range as evidence.
    all_identities = _known_identities(graph)
    total_identities = len(all_identities)
    _id_cap = (DEFAULT_MAX_IDENTITIES if max_identities is None
               else max(0, int(max_identities)))
    identities_shown = all_identities[:_id_cap]

    def _fd(f):
        fd = {"title": f.title, "severity": f.severity, "confidence": f.confidence,
              "hosts": [_host_label(graph, x) for x in f.asset_ids],
              "summary": f.summary, "mitre": f.mitre, "kind": f.kind, "ts": f.ts}
        # OFF for the narrative, ON for the advisory. The advisory is REQUIRED to
        # cite finding_ids and entity_ids, and _ground() deletes anything citing an
        # id that is not in the graph -- but this payload carried no ids at all, so
        # the model had nothing to quote and every group and hypothesis it produced
        # was discarded. Measured: zero hypotheses on every advisory ever run on a
        # live box, across two different models. No model can pass that.
        #
        # The narrative must NOT get them: it writes prose for a customer, and an
        # id in the payload is an id it may print into the report.
        if include_ids:
            fd["id"] = f.id
        # EXPLICIT: surface real per-event evidence so the narrative can cite specifics.
        if eff_detail == "explicit" and (sev.at_least(f.severity, "high")
                                         or f.kind == "cross_host"):
            ev = _finding_evidence(graph, f)
            if ev:
                fd["evidence"] = ev
        return fd

    altitude = _resolve_altitude(graph, window=window, min_severity=min_severity)[0]
    out = {
        "case_id": graph.case_id,
        "report_detail": eff_detail,
        # Scope shape the model reads to know its ALTITUDE (macro triage map vs one
        # focused theory). Span is EVIDENCE-based (finding ts), not the window.
        "scope": {
            "hosts": len(assets),
            "findings": total_findings,
            # What actually fits in this payload. When findings_shown < findings the
            # model is reading a SAMPLE and must not state the sample as the total.
            "findings_shown": len(findings),
            # Same contract for the other trimmed collections: *_shown < * means the
            # payload carries a SAMPLE, and the sample must never be counted as the
            # population. top_entities is additionally ranked by anomaly, so it is a
            # selection even when nothing was dropped.
            "entities": total_entities,
            "entities_shown": len(ents),
            "identities": total_identities,
            "identities_shown": len(identities_shown),
            "cross_host": sum(1 for f in findings if f.kind == "cross_host"),
            "evidence_span_days": _evidence_span_days(findings),
            "altitude": altitude,
        },
        "assets": [{"id": a.id, "host": a.label, "severity": a.severity} for a in assets],
        "findings": [_fd(f) for f in findings],
        # Same set as `findings` above — filtered identically so a trimmed payload
        # never carries a timeline row for a finding it dropped.
        "timeline": [t for t in timeline(graph, window=window)
                     if max_findings is None or t.get("finding_id") in kept_ids],
        "top_entities": [dict({"type": e.type, "label": e.label, "severity": e.severity,
                               "anomaly": e.anomaly, "flags": e.flags,
                               "hosts": [_host_label(graph, x) for x in _assets_of(e)]},
                              **({"id": e.id} if include_ids else {}))
                         for e in ents],
        # Every identity the Identities tab shows, independent of anomaly score —
        # see _known_identities(). Cheap relative to the rest of this payload;
        # keeps "who is X" answerable for every real person in the case, not only
        # the ones a finding happens to be attached to.
        "identities": identities_shown,
        # Per-host coverage roll-up. Exists because a narrative written from
        # `findings` alone follows finding VOLUME, and volume lives on noisy
        # workstations: a domain controller with 7 findings (two of them severe)
        # got a passing mention while a workstation with 27 got the whole story.
        # This states every host once, with its weight, so no host can be skipped
        # silently and the model can see which are infrastructure.
        "host_coverage": _host_coverage(graph, assets, findings),
        # hash -> filename, so the narrative can cite any hash it sees WITH its file
        # (e.g. cross-host shared-binary hashes). Built from the source_name captured at
        # fuse time; generic, resolves custom/unknown binaries too. Keeps the report
        # actionable: a bare hash is not.
        "file_hashes": {fh: nm for fh, nm in _hash_name_map(graph).items()},
    }
    if include_timeframes and altitude == "macro":
        # Fixed, numbered windows -- the same list as the zoom cards -- so the
        # model writes one section per real window and cannot invent one.
        #
        # OPT-IN, because distilled() serves four callers. Adding this
        # unconditionally handed the advisory, chat and investigate a key their
        # prompts never describe -- payload a model has no instructions for is
        # exactly what makes one behave oddly. Only the macro REPORT prompt
        # documents `timeframes`, so only it asks for them.
        out["timeframes"] = timeframes_for_payload(
            zoom_targets(graph, window=window, min_severity=min_severity))
    return out


# Hosts whose ROLE matters more than their finding count. A CA or DC with a
# handful of findings outranks a workstation with dozens, and the narrative has
# to say so — certificate findings anywhere in a case become a different class
# of problem the moment they touch the CA.
_HOST_ROLE_HINTS = (
    ("dc", "domain controller"), ("ca", "certificate authority"),
    ("mecm", "config manager / software distribution"),
    ("sccm", "config manager / software distribution"),
    ("sql", "database server"), ("exch", "mail server"),
)


def _host_role(label: str) -> str:
    """Best-effort role from the hostname. Naming is a convention, not a fact, so
    this is a HINT for the narrative to verify — never asserted as ground truth."""
    lo = (label or "").lower()
    for token, role in _HOST_ROLE_HINTS:
        # token as a word-ish fragment: ALDC02 -> dc, ALCA01 -> ca
        if token in lo:
            return role
    return ""


def _host_coverage(graph, assets, findings) -> list:
    """One row per host: weight, span and role hint — so every host is visible to
    the narrative even when its finding count is small."""
    rows = []
    for a in assets:
        label = a.label
        fs = [f for f in findings if a.id in (f.asset_ids or [])]
        ts = sorted([f.ts for f in fs if f.ts])
        row = {
            "host": label,
            "severity": a.severity,
            "finding_count": len(fs),
            "first_activity": ts[0] if ts else None,
            "last_activity": ts[-1] if ts else None,
            "cross_host_findings": sum(1 for f in fs if f.kind == "cross_host"),
        }
        role = _host_role(label)
        if role:
            row["role_hint"] = role
        rows.append(row)
    # Severity first, then volume: the order the narrative should prioritise, not
    # the order finding counts alone would suggest.
    _sev = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    rows.sort(key=lambda r: (_sev.get(r["severity"], 9), -r["finding_count"]))
    return rows


def distilled(graph, *, window=None, min_severity="informational", max_entities=60,
              budget_chars=None, detail="summary", max_identities=None,
              include_ids=False, include_timeframes=False):
    """Compact, in-window, high-signal payload — what a real LLM would get.

    If ``budget_chars`` is set and the payload exceeds it, halve ``max_entities``
    up to ``budget.MAX_STEPDOWNS`` times. Findings/assets/timeline are always kept
    (they are the signal); only the ranked ``top_entities`` tail is trimmed.
    ``detail`` ('auto'/'explicit'/'summary') controls per-event evidence — explicit
    adds the real cmdline/path/hash to each high finding (see _resolve_detail)."""
    from . import budget as _b
    p = _distilled_at(graph, window=window, min_severity=min_severity,
                      max_entities=max_entities, detail=detail,
                      max_identities=max_identities, include_ids=include_ids,
                      include_timeframes=include_timeframes)
    if not budget_chars:
        return p

    # The stepdown must shrink what the payload is actually MADE OF. Measured on a
    # real case: findings 51% + timeline 43% = 94% of the payload, entities 3.4%.
    # Halving only entities therefore reclaimed ~1.7k chars of a 99.7k payload that
    # was 3x over a 32k budget — it destroyed the cheapest, most useful context
    # (entities 60 -> 15), achieved nothing, then shipped over budget anyway.
    # So findings (and the timeline derived from them) shrink too, lowest-severity
    # first; _trim_findings never drops anything >= high.
    # Trim in order of COST PER UNIT OF VALUE — cut the bulk before the cheap,
    # high-value context. Entities are 3.4% of the payload and are what makes
    # "who/what is X" answerable, so they are the LAST thing to go, not the first
    # (the previous loop halved them immediately, which is the bug this fixes).
    steps = 0
    eff_ident = DEFAULT_MAX_IDENTITIES if max_identities is None else max_identities
    eff_findings = len(p.get("findings") or [])
    while _b.over_budget(p, budget_chars) and steps < _b.MAX_STEPDOWNS:
        before = (eff_findings, max_entities, eff_ident)
        if eff_findings > _MIN_FINDINGS:
            eff_findings = max(_MIN_FINDINGS, eff_findings // 2)   # the 94%
        else:
            # findings exhausted (or all remaining are >= high and exempt) — now
            # spend the cheap stuff
            max_entities = max(5, max_entities // 2)
            eff_ident = max(10, eff_ident // 2)
        if (eff_findings, max_entities, eff_ident) == before:
            break                                    # nothing left to give
        # include_ids must survive the stepdown too: a payload that goes over
        # budget rebuilds here, and dropping the flag would silently return the
        # advisory to citing ids it was never given.
        p = _distilled_at(graph, window=window, min_severity=min_severity,
                          max_entities=max_entities, detail=detail,
                          max_identities=eff_ident, max_findings=eff_findings,
                          include_ids=include_ids,
                          include_timeframes=include_timeframes)
        steps += 1
    # LAST RESORT — still over budget after the stepdowns. Measured: a case with
    # thousands of findings blows through it (120 hosts / 4,321 findings produced a
    # 2.6 MB payload against a 708 KB budget, 3.7x over) because MAX_STEPDOWNS caps
    # the halving AND _trim_findings deliberately never drops anything >= high. So
    # the budget silently stopped binding exactly when it mattered most.
    #
    # Do NOT drop signal to fix that. COLLAPSE it instead: the same detection
    # repeating across many hosts is one fact, not N — state it once with its count,
    # host list and time span (the treatment the rendered timeline already uses).
    # Every distinct (title, severity) survives, so nothing an analyst could act on
    # is lost; only the repetition goes.
    if _b.over_budget(p, budget_chars) and (p.get("findings") or []):
        p["findings"] = _collapse_findings(p["findings"])
        p["findings_collapsed"] = True
    # The timeline is the real bulk once findings collapse — measured at 120 hosts it
    # was 90.8% of the payload (1.2 MB of 1.34 MB). Collapse it the same way: one row
    # per (detection, severity) with its count, hosts and span.
    if _b.over_budget(p, budget_chars) and (p.get("timeline") or []):
        p["timeline"] = _collapse_findings(p["timeline"])
        p["timeline_collapsed"] = True
    return p


def _collapse_findings(findings):
    """Group repeated findings by (title, severity): one row carrying the count, the
    hosts it spans and its first/last time. Severity-preserving by construction — no
    level is favoured or dropped, repetition is simply stated once."""
    from collections import OrderedDict

    def _hosts_of(f):
        """Findings carry `hosts` (list); timeline rows carry `host` (comma string)."""
        hs = f.get("hosts")
        if isinstance(hs, list):
            return [h for h in hs if h]
        h = f.get("host") or hs
        if isinstance(h, str) and h.strip() and h != "-":
            return [x.strip() for x in h.split(",") if x.strip()]
        return []

    def _norm(f):
        """Titles EMBED the host ("SIGMA: X on FLEET-042"), so grouping on the raw
        title collapses nothing — every title is unique and the pass is a no-op
        (measured: 4,321 titles -> 4,321 groups, 1.4 KB saved of 2.6 MB). Strip the
        row's OWN host off the tail so the same detection across hosts groups."""
        t = f.get("title") or ""
        for h in _hosts_of(f):
            if t.endswith(f" on {h}"):
                return t[: -(len(h) + 4)]
        return t

    groups: "OrderedDict[tuple, dict]" = OrderedDict()
    for f in findings:
        key = (_norm(f), f.get("severity"))
        g = groups.get(key)
        if g is None:
            groups[key] = {"title": _norm(f), "severity": f.get("severity"),
                           "confidence": f.get("confidence"), "kind": f.get("kind"),
                           "mitre": f.get("mitre"), "summary": f.get("summary"),
                           "hosts": list(_hosts_of(f)), "count": 1,
                           "first_ts": f.get("ts"), "last_ts": f.get("ts")}
            # Carry the collapsed rows' ids when the caller asked for them. Rebuilt
            # dicts otherwise drop them, and the advisory -- which MUST cite
            # finding_ids -- would silently go back to citing nothing on exactly the
            # large cases that trigger a collapse and most need grouping. A list,
            # because a collapsed row genuinely IS several findings. Absent when the
            # source rows carry no id (the narrative payload), so nothing is invented.
            if f.get("id"):
                groups[key]["ids"] = [f["id"]]
            continue
        g["count"] += 1
        if f.get("id"):
            g.setdefault("ids", []).append(f["id"])
        for h in _hosts_of(f):
            if h not in g["hosts"]:
                g["hosts"].append(h)
        ts = f.get("ts")
        if ts:
            if not g["first_ts"] or ts < g["first_ts"]:
                g["first_ts"] = ts
            if not g["last_ts"] or ts > g["last_ts"]:
                g["last_ts"] = ts
    out = []
    for g in groups.values():
        hosts = g["hosts"]
        if len(hosts) > 8:                       # host list itself can be the bulk
            g["hosts"] = hosts[:8]
            g["hosts_total"] = len(hosts)
        if g["count"] == 1:
            g.pop("count", None)
            g["ts"] = g.pop("first_ts", None)
            g.pop("last_ts", None)
            # A row that collapsed nothing is still one finding: give it back the
            # plain `id` the uncollapsed payload would have had, so a consumer
            # never has to special-case the shape.
            if len(g.get("ids") or []) == 1:
                g["id"] = g.pop("ids")[0]
        out.append(g)
    return out


def _finding_dict(graph, f):
    return {"title": f.title, "severity": f.severity, "confidence": f.confidence,
            "hosts": [_host_label(graph, x) for x in f.asset_ids],
            "summary": f.summary, "mitre": f.mitre, "kind": f.kind, "ts": f.ts}


def _entity_dict(graph, e):
    return {"type": e.type, "label": e.label, "severity": e.severity, "anomaly": e.anomaly,
            "flags": e.flags, "hosts": [_host_label(graph, x) for x in _assets_of(e)]}


def chat_subgraph(graph, question, *, window=None, min_severity="informational",
                  max_entities=20, pin_ids=None, focus_labels=None):
    """Question-scoped subgraph for chat — far smaller than the whole distilled graph,
    so chat tokens stay flat as cases grow. ALWAYS includes every >=high finding
    (escalation-critical facts must never be retrieved away), plus the findings and
    entities lexically relevant to the question.

    `pin_ids` are entities resolved from the question (services/fusion/resolve.py)
    — a pinned host gets its FULL context (all its findings, not just >=high) so
    'why is desktop-566 bad?' loads everything about DESKTOP-566AT85. `focus_labels`
    is echoed back in the payload so the assistant states which host it answered on
    (the analyst can catch a mis-resolution)."""
    q = (question or "").lower()
    pin_ids = set(pin_ids or [])
    _, findings = scope(graph, window=window, min_severity=min_severity)
    picked: dict = {f.id: f for f in findings if sev.at_least(f.severity, "high")}
    rel_ents: list = []

    # Resolved pins: full context for the named host/account (every finding on it).
    pin_asset_ids = {i for i in pin_ids if i.startswith("asset:")}
    for f in findings:
        if pin_asset_ids & set(f.asset_ids) or (pin_ids & set(f.entity_ids)):
            picked[f.id] = f
    for e in graph.entities.values():
        if e.id in pin_ids:
            rel_ents.append(e)

    for a in graph.by_type("asset"):                       # host mentioned (lexical)
        if a.label and a.label.lower() in q:
            for f in findings:
                if a.id in f.asset_ids:
                    picked[f.id] = f
    for e in graph.entities.values():                      # ioc/account/process mentioned
        if e.type in ("ioc", "account", "process", "service") and e.label \
                and e.label.lower() in q:
            rel_ents.append(e)
            for f in findings:
                if e.id in f.entity_ids:
                    picked[f.id] = f
    intents = [(("lateral", "move", "pivot", "spread"), lambda f: f.kind == "cross_host"),
               (("persist", "service", "autorun", "task"),
                lambda f: any(k in f.title.lower() for k in ("service", "persist", "task"))),
               (("vuln", "cve", "patch"), lambda f: f.title.lower().startswith("vulnerab")),
               (("inject", "c2", "beacon"),
                lambda f: any(k in f.title.lower() for k in ("inject", "c2", "indicator")))]
    for kws, pred in intents:
        if any(k in q for k in kws):
            for f in findings:
                if pred(f):
                    picked[f.id] = f

    # entity budget: question-relevant first, then key identities (accounts seen on
    # >1 host — central to infrastructure insight, often only informational severity),
    # then high-anomaly fill.
    key_accts = sorted((e for e in graph.entities.values()
                        if e.type == "account" and len(_assets_of(e)) > 1),
                       key=lambda e: -len(_assets_of(e)))
    fill = sorted((e for e in graph.entities.values()
                   if e.type != "asset" and sev.at_least(e.severity, "high")),
                  key=lambda e: -e.anomaly)
    ents, seen = [], set()
    for e in rel_ents + key_accts + fill:
        if e.id not in seen:
            seen.add(e.id); ents.append(e)
        if len(ents) >= max_entities:
            break
    out = {
        "case_id": graph.case_id,
        "question_scope": True,
        "assets": [{"id": a.id, "host": a.label, "severity": a.severity}
                   for a in graph.by_type("asset")],
        "findings": [_finding_dict(graph, f) for f in picked.values()],
        "top_entities": [_entity_dict(graph, e) for e in ents],
    }
    if focus_labels:
        # The assistant must state which identity it resolved to, so a wrong
        # resolution is visible to the analyst before they act on it.
        out["resolved_focus"] = list(focus_labels)
    return out


# ------------------------------------------------------------------ report


def _sev_tally(findings):
    t = {lv: 0 for lv in sev.LEVELS}
    for f in findings:
        t[f.severity] = t.get(f.severity, 0) + 1
    return t


def _join_nat(items) -> str:
    """Oxford-comma natural-language join: [a,b,c] -> 'a, b, and c'."""
    items = [i for i in items if i]
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + f", and {items[-1]}"


def _exec_summary(graph, assets, findings, *, initial_access=None, window=None) -> str:
    """A plain-language, story-telling executive summary: what happened in the
    organization, how the adversary operated, how far it spread, and the bottom line.
    Deterministic — the live LLM replaces this with a richer narrative."""
    if not findings:
        return ("This investigation did not surface findings at or above the configured "
                "severity threshold within the selected window. No adversary activity is "
                "indicated; routine monitoring is sufficient.")
    # Rank by risk_score first (same order as the Identity Risk table + Attack
    # Assessment) so "most affected" is consistent everywhere in the report.
    hosts = sorted(assets, key=lambda a: (-(a.attrs.get("risk_score") or 0),
                                          -sev.rank(a.severity)))
    crit = [f for f in findings if sev.at_least(f.severity, "critical")]
    high = [f for f in findings if f.severity == "high"]
    xh = [f for f in findings if f.kind == "cross_host"]
    affected = [a for a in assets if any(a.id in f.asset_ids for f in findings)]
    order = [lab for lab, _ in _ASSESS_TACTICS]
    fleet: dict = {}
    for a in assets:
        for lab in _host_tactics(findings, a.id):
            fleet.setdefault(lab, set()).add(a.label)
    objectives = [lab for lab in order if lab in fleet]
    tl = timeline(graph, window=window)
    first_ts = tl[0]["ts"] if tl else None
    last_ts = tl[-1]["ts"] if tl else None

    bits = []
    sev_word = "critical" if crit else ("high" if high else "moderate")
    bits.append(
        f"This investigation correlated suspicious activity across "
        f"**{len(affected) or len(assets)} of {len(assets)} host(s)** and surfaced "
        f"**{len(findings)} finding(s)** ({len(crit)} critical, {len(high)} high), "
        f"placing the overall severity of this incident at **{sev_word}**.")
    if first_ts:
        span = (f"between `{first_ts}` and `{last_ts}`" if last_ts and last_ts != first_ts
                else f"around `{first_ts}`")
        bits.append("The earliest time-anchored activity runs " + span
                    + (f", with initial access estimated near `{initial_access}`." if initial_access
                       else "."))
    if objectives:
        did = _join_nat([_TACTIC_VERB.get(l, l.lower()) for l in objectives])
        bits.append(f"Across the environment the adversary {did} — consistent with a "
                    f"hands-on-keyboard intrusion rather than isolated, unrelated alerts."
                    if (crit or high) else
                    f"Across the environment the observed activity involved {did}.")
    if hosts:
        w = hosts[0]
        wt = [lab for lab in order if lab in _host_tactics(findings, w.id)]
        nf = sum(1 for f in findings if w.id in f.asset_ids)
        focus = (" — the focal point, where activity spanned "
                 + _join_nat([_TACTIC_SHORT.get(l, l.lower()) for l in wt[:5]])) if wt else ""
        bits.append(f"**{w.label}** ({w.severity}, {nf} finding(s)) is the most affected "
                    f"system{focus}.")
    if xh:
        bits.append(f"Critically, **{len(xh)} finding(s)** correlate across multiple hosts — "
                    f"evidence the activity spread laterally or shares adversary infrastructure, "
                    f"so this should be treated as an environment-wide event, not single-host alerts.")
    if crit or high:
        bits.append("**Bottom line:** immediate containment of the priority hosts and a "
                    "deeper forensic review (memory, full timeline) are recommended before "
                    "the adversary consolidates access further.")
    return " ".join(bits)




def narrative_md(graph, *, window=None, min_severity="informational",
                 initial_access=None, case_name="Case") -> str:
    """The LLM-REPLACEABLE prose: exec summary, incident overview, attack narrative.
    When the real LLM is wired it regenerates this from ``distilled()`` — the
    deterministic fact tables in ``facts_md`` are never sent to it."""
    assets, findings = scope(graph, window=window, min_severity=min_severity)
    win = (f"{(window or {}).get('start') or 'open'} → {(window or {}).get('end') or 'now'}"
           if window else "all")
    out: list[str] = [f"# Incident Case Report — {case_name}\n"]
    out.append(f"_Scope: {len(assets)} host(s) · window {win} · initial access ≈ "
               f"{initial_access or 'unknown'} · severity ≥ {min_severity} · "
               f"{len(findings)} findings_\n")
    out.append("## Executive Summary\n")
    out.append(_exec_summary(graph, assets, findings,
                             initial_access=initial_access, window=window) + "\n")
    # NOTE: the deterministic "Incident Overview" + phase-grouped "Attack Narrative"
    # were removed — they duplicated the Executive Summary + the single Timeline. The
    # live-LLM path replaces this whole function with a real narrative.
    return "\n".join(out)


_STATE_LABEL = {"real": "True Positive", "not_real": "False Positive",
                "known_it": "Known (IT-confirmed)", "pending": "Pending"}


def _analyst_validations_md(graph, dispositions, validations) -> str:
    """What the analyst decided in the Timeline — so the report reflects the triage
    (confirmed real, dismissed as FP, or IT-acknowledged). Integration point with
    the Timeline tab."""
    title_of = {f.id: f.title for f in graph.findings}
    buckets = {"real": [], "not_real": [], "known_it": []}
    seen = set()
    for v in (validations or []):
        fid, st = v.get("finding_id"), v.get("status")
        if st in buckets and fid not in seen:
            seen.add(fid)
            buckets[st].append(title_of.get(fid, str(fid)))
    for d in (dispositions or []):                 # chat-driven triage not in the timeline
        tgt = d.get("target")
        if tgt in seen:
            continue
        seen.add(tgt)
        buckets["known_it" if d.get("attribution") == "it_admin" else "not_real"].append(
            title_of.get(tgt, str(tgt)))
    if not any(buckets.values()):
        return ""
    out = ["## Analyst Validations\n",
           "_Operator triage from the Timeline. False-positive and known/expected "
           "items are suppressed from risk scoring._\n"]
    for st in ("real", "not_real", "known_it"):
        items = buckets[st]
        if items:
            out.append(f"**{_STATE_LABEL[st]} ({len(items)}):**")
            out += [f"- {t}" for t in items[:20]]
            out.append("")
    return "\n".join(out)


def _recommendations_md(graph, findings, assets) -> str:
    """Actionable, deterministic next steps derived from the findings (containment →
    eradication → credentials → network → patching → deeper collection → evidence)."""
    recs: list[tuple] = []
    hot = sorted((a for a in assets if sev.at_least(a.severity, "high")),
                 key=lambda a: -sev.rank(a.severity))
    if hot:
        recs.append(("Containment", "Isolate the most-affected host(s) from the network "
                     "pending eradication: " + ", ".join(a.label for a in hot[:6]) + "."))
    pers = list(dict.fromkeys(f.title for f in findings
                if any(k in f.title.lower() for k in ("service", "persist", "task", "autorun"))))
    if pers:
        recs.append(("Eradication", "Remove the malicious persistence and confirm it does "
                     "not re-create: " + "; ".join(pers[:4]) + "."))
    xacct = [e for e in graph.by_type("account") if "cross_host" in (e.flags or [])]
    if xacct:
        recs.append(("Credentials", "Reset and review the accounts used across multiple "
                     "hosts (" + ", ".join(e.label for e in xacct[:6]) + "); rotate tier-0 "
                     "credentials if a privileged/domain account is involved."))
    # Only recommend blocking VALIDATED / high-confidence indicators — never the
    # merely-observed hashes (don't send the SOC to block a benign binary).
    kept_iocs = [i for i, _ in _high_confidence_iocs(graph)[0]]
    if kept_iocs:
        recs.append(("Network", "Block these indicators at the perimeter / EDR and hunt for "
                     "further callbacks: " + ", ".join(f"`{e.label}`" for e in kept_iocs[:8]) + "."))
    if [f for f in findings if f.title.lower().startswith("vulnerab")]:
        recs.append(("Patching", "Patch the exposed vulnerabilities on the affected hosts."))
    esc = [a for a in assets if a.attrs.get("escalate")]
    if esc:
        recs.append(("Deeper collection", "Collect memory + a full timeline (Timesketch) on "
                     + ", ".join(a.label for a in esc[:6]) + " — malicious under broad "
                     "collection but lacking deep forensics."))
    recs.append(("Evidence preservation", "Capture disk + memory images and relevant logs for "
                 "the confirmed-compromised hosts before remediation."))
    out = ["## Recommendations\n"]
    out += [f"{i + 1}. **{title}** — {body}" for i, (title, body) in enumerate(recs)]
    out.append("")
    return "\n".join(out)



# Collector labels shown to the operator. The graph records the INTERNAL module that
# produced an entity, but several internal names are the same COLLECTOR from the
# analyst's point of view — a Velociraptor collection and a Velociraptor hunt are both
# just "velociraptor". Showing the internal split as if it were extra coverage
# overstates what was collected. Generic map, applied wherever coverage is rendered;
# add a line here rather than special-casing a call site.
_COLLECTOR_LABEL = {
    "agentic": "velociraptor",
    "velociraptor_collection": "velociraptor",
    "velociraptor_upload": "velociraptor",
    "velociraptor_hunt": "velociraptor",
    "velociraptor_offline_import": "velociraptor",
    "velociraptor_adopt": "velociraptor",
}


def _collectors(modules) -> list:
    """Canonical, de-duplicated collector names, order preserved."""
    out = []
    for m in (modules or []):
        lbl = _COLLECTOR_LABEL.get(str(m).strip().lower(), str(m).strip())
        if lbl and lbl not in out:
            out.append(lbl)
    return out


def risk_table(graph, *, window=None, min_severity="informational") -> list:
    """Per-endpoint ('identity') risk rows for the 'who to focus on first + why'
    table. One row per asset, sorted by risk_score desc. Each row carries the
    score, the severity rollup, module coverage, escalate/deep flags, a
    per-severity finding tally, and the CONCRETE top reasons (highest-severity
    findings) driving the score — so the table answers both 'which client' and
    'why', deterministically (no LLM). Drives the report section + /risk API."""
    assets, findings = scope(graph, window=window, min_severity=min_severity)
    # Score against the SCOPED findings, not the entity's fusion-time attributes.
    # Those are computed over every finding ever, so a host whose activity all falls
    # outside the window rendered as "high, 61" on the same row as "0/0/0 - no
    # findings in window". Same formula (correlate.score_assets_over), one definition.
    from .correlate import score_assets_over
    scored = score_assets_over(assets, findings, len(assets))
    rows = []
    for a in assets:
        afind = [f for f in findings if a.id in f.asset_ids]
        sc = scored.get(a.id) or {}
        tally = {lv: 0 for lv in sev.LEVELS}
        for f in afind:
            if f.severity in tally:
                tally[f.severity] += 1
        # Top reasons = highest-severity findings first, deduped by title, capped.
        seen, reasons = set(), []
        for f in sorted(afind, key=lambda f: (-sev.rank(f.severity), f.title or "")):
            t = (f.title or "").strip()
            if not t or t.lower() in seen:
                continue
            seen.add(t.lower())
            reasons.append(t + (" (cross-host)" if f.kind == "cross_host" else ""))
            if len(reasons) >= 4:
                break
        modules = a.attrs.get("modules") or []
        escalate, deep = bool(a.attrs.get("escalate")), bool(a.attrs.get("deep"))
        if escalate:
            action = "Deep-dive now — run memory + Timesketch"
        elif deep:
            action = "Deep coverage done — review findings"
        elif sev.at_least(sc.get("severity") or "informational", "medium"):
            action = "Triage / monitor"
        else:
            action = "Low priority"
        rows.append({
            "client_id": a.id,
            "host": a.label,
            "hostname": a.attrs.get("hostname") or a.label,
            "risk_score": int(sc.get("risk_score") or 0),
            "risk_intensity": float(sc.get("risk_intensity") or 0),
            "severity": sc.get("severity") or "informational",
            "escalate": escalate,
            "deep": deep,
            "modules": _collectors(modules),
            "finding_count": len(afind),
            "by_severity": tally,
            "cross_host": any(f.kind == "cross_host" for f in afind),
            "reasons": reasons,
            "why": "; ".join(reasons[:3]) or "no findings in window",
            "next_action": action,
        })
    # risk_score encodes the tier band; raw intensity breaks display-integer ties
    # so 'who is #1 of the hosts showing 100' is always answered.
    rows.sort(key=lambda r: (-r["risk_score"], -r["risk_intensity"],
                             -sev.rank(r["severity"]), r["host"]))
    return rows


def risk_table_md(graph, *, window=None, min_severity="informational") -> str:
    """Markdown rendering of risk_table() — the 'Identity Risk / focus order'
    section. Deterministic; appended verbatim, never sent to the LLM."""
    rows = risk_table(graph, window=window, min_severity=min_severity)
    if not rows:
        return ""
    # "Host Risk", not "Identity Risk": every column here is a HOST (Host, Risk,
    # Severity, Findings, Coverage). It predated the Identities feature and the
    # old name now sits beside a real "Identities and Attribution" section about
    # people, so the two read as the same thing when they are not.
    out = ["## Host Risk — who to focus on first\n",
           "Endpoints ranked by risk (0-100) — severity tier sets the band "
           "(critical 80-100, high 60-79, medium 40-59, low 20-39) so a 'critical' host "
           "always outranks a 'high' one; finding intensity orders hosts within the band. "
           "Cross-host findings are weighted relative to fleet size. _Why_ = the top "
           "findings driving the score.\n",
           # No "Next" column: it restated the same three canned strings on every row
           # (escalate / deep-done / triage), so it added width without information.
           # The recommended action belongs in the narrative's Priority actions, which
           # is case-specific.
           "| # | Host | Risk | Severity | Findings (C/H/M) | Why | Coverage |",
           "|---|------|-----:|----------|------------------|-----|----------|"]
    # At fleet scale this table becomes a second wall of text. Rank order already
    # puts what matters on top, so show that and COUNT the tail rather than
    # printing a page of nominal hosts (the tail is still in the console).
    shown = rows[:RISK_TABLE_MAX_ROWS]
    for i, r in enumerate(shown, 1):
        cov = ", ".join(r["modules"]) or "—"
        cov += " 🔺" if r["escalate"] else (" ✓deep" if r["deep"] else "")
        t = r["by_severity"]
        chm = f"{t.get('critical',0)}/{t.get('high',0)}/{t.get('medium',0)}"
        why = (r["why"] or "").replace("|", "／")[:140]
        out.append(f"| {i} | **{r['host']}** | {r['risk_score']} | {r['severity']} | "
                   f"{chm} | {why} | {cov} |")
    if len(rows) > RISK_TABLE_MAX_ROWS:
        rest = rows[RISK_TABLE_MAX_ROWS:]
        top = max((r["risk_score"] for r in rest), default=0)
        out.append("")
        out.append(f"_… and {len(rest)} further host(s), all scoring ≤ {top} "
                   "(ranked below the focus set above) — full ranking in the console._")
    out.append("")
    return "\n".join(out)


# ATT&CK-tactic synthesis for the Attack Assessment — categorises each detection by
# what the adversary was DOING (objective), turning a flat detection list into
# analysis. Kept separate from correlate's coord proxy so it never affects calibration.
_ASSESS_TACTICS = [
    ("Execution",
     ("powershell", "encoded", "base64", "scriptblock", "mshta", "rundll", "wscript",
      "cscript", "iex", "frombase64", "obfuscat", "wmi exec", "script interpreter")),
    ("Process Injection", ("inject", "hollow", " rwx")),
    ("Credential Access",
     ("lsass", "mimikatz", "credential", "ntds", "sam dump", "password dump", "dumper",
      "rubeus", "kerberos", "dcsync", "secretsdump", "hashdump", "wdigest", "certipy",
      "krbrelay", "petitpotam", "safetykatz", "sharpdump", "seatbelt")),
    ("Defense Evasion",
     ("log file cleared", "eventlog cleared", "disable", "bypass", "amsi", "etw",
      "defender", "real-time protection", "threat detection", "tamper", "uac",
      "renamed", "masquerad", "rename of", "exploitation framework", "hacktool",
      "relevant file paths", "antivirus")),
    ("Discovery",
     ("discovery", "recon", "whoami", "nltest", "enumerat", "adfind", "bloodhound",
      "sharphound", "ldap", "net group", "ip scanner", "epmap", "powerscan")),
    ("Lateral Movement",
     ("rdp", "psexec", "smbexec", "wmiexec", "crackmapexec", "netexec", "remote desktop",
      "outbound rdp", "pass the", "across ", "lateral")),
    ("Persistence",
     ("autorun", "run key", "service install", "scheduled task", "new service",
      "registry run", "startup", "service creation", "service path", "service name",
      "schtasks", "boot", "sharpersist", "inveigh")),
    ("Command & Control",
     ("beacon", "cobalt strike", "download", "webrequest", "dns query", "named pipe",
      "file sharing", "callback", "anydesk", "teamviewer", "tailscale", "quick assist")),
    ("Exfiltration / Tooling", ("data transfer", "7-zip", "archive", "rclone", "exfil")),
]

# Natural-language verb phrase per tactic (for the prose Attack Assessment + exec
# summary) and a short noun form (for inline lists), so the report reads as sentences
# describing what the adversary DID — not a flat list of detection titles.
_TACTIC_VERB = {
    "Execution": "executed code on the host",
    "Process Injection": "injected code into running processes",
    "Credential Access": "harvested credentials",
    "Defense Evasion": "took steps to evade or disable defenses",
    "Discovery": "performed host and domain reconnaissance",
    "Lateral Movement": "moved laterally to other systems",
    "Persistence": "established persistence",
    "Command & Control": "established command-and-control",
    "Exfiltration / Tooling": "staged tooling or data for exfiltration",
}
_TACTIC_SHORT = {
    "Execution": "code execution", "Process Injection": "process injection",
    "Credential Access": "credential theft", "Defense Evasion": "defense evasion",
    "Discovery": "reconnaissance", "Lateral Movement": "lateral movement",
    "Persistence": "persistence", "Command & Control": "command-and-control",
    "Exfiltration / Tooling": "exfiltration tooling",
}


def _clean_det(title: str) -> str:
    """A detection's display name: drop 'SIGMA:'/rule wrappers + the trailing host."""
    import re as _re
    t = title
    for p in ("Hayabusa/SIGMA rule ", "SIGMA: ", "Detection '", "Detection: "):
        if t.startswith(p):
            t = t[len(p):]
    t = _re.sub(r"\s+(on|across)\s+.*$", "", t)
    return t.strip().strip("'\"").rstrip(".")


def _host_tactics(findings, host_id) -> dict:
    """{tactic-label: {detection names}} for one host — by adversary objective."""
    buckets: dict = {}
    for f in findings:
        if host_id not in f.asset_ids:
            continue
        tl = f.title.lower()
        for label, kws in _ASSESS_TACTICS:   # first (highest-priority) tactic wins — one bucket
            if any(w in tl for w in kws) or (label == "Lateral Movement" and f.kind == "cross_host"):
                buckets.setdefault(label, set()).add(_clean_det(f.title))
                break
    return buckets


def _attack_assessment(graph, assets, findings, *, window=None, initial_access=None) -> str:
    """Reconstruct the intrusion as ONE infrastructure-wide story — how the adversary
    likely entered, moved between hosts (shared credentials / reused tooling), and what
    they did — ordered by the timeline rather than treating each host in isolation.
    More-malicious hosts (higher risk score / severity) get the deeper write-up."""
    order = [lab for lab, _ in _ASSESS_TACTICS]
    prof = []
    for a in assets:
        af = [f for f in findings if a.id in f.asset_ids]
        if not af:
            continue
        tac = _host_tactics(findings, a.id)
        ts_list = sorted(f.ts for f in af if f.ts)
        prof.append({"host": a.label, "sev": a.severity,
                     "risk": int(a.attrs.get("risk_score") or 0),
                     "tactics": [l for l in order if l in tac], "tac_map": tac,
                     "first": ts_list[0] if ts_list else None, "n": len(af)})
    if not prof:
        return ""
    chrono = sorted(prof, key=lambda p: (p["first"] or "9999", -p["risk"]))
    worst = max(prof, key=lambda p: (p["risk"], sev.rank(p["sev"])))
    entry = chrono[0]

    # how the adversary moved between systems (the "infrastructure" view)
    xacct = [e for e in graph.by_type("account") if "cross_host" in (e.flags or [])]
    xhash = [e for e in graph.by_type("ioc")
             if e.attrs.get("ioc_kind") == "hash" and "cross_host" in (e.flags or [])]
    xfind = [f for f in findings if f.kind == "cross_host"]

    out = ["## Attack Assessment\n"]
    # 1. opening — entry point + scope, as a story
    lead = (f"The earliest observed activity was on **{entry['host']}** "
            + (f"around `{entry['first']}`" if entry['first'] else "(time not anchored)")
            + (f", where the adversary "
               + _join_nat([_TACTIC_VERB.get(l, l.lower()) for l in entry['tactics'][:3]])
               if entry['tactics'] else "") + ".")
    if initial_access:
        lead += f" Initial access is estimated near `{initial_access}`."
    out.append(f"This reconstructs the likely course of the intrusion across "
               f"**{len(prof)} affected host(s)** as a single campaign — ordered as it "
               f"unfolded, not host-by-host in isolation. {lead}")

    # 2. lateral movement — how he pivoted across the infrastructure
    move = []
    if xacct:
        move.append("the account(s) " + _join_nat([f"`{e.label}`" for e in xacct[:3]])
                    + " authenticated on multiple hosts")
    if xhash:
        move.append(f"{len(xhash)} tool/binary hash(es) were reused across hosts")
    if xfind and not (xacct or xhash):
        move.append(_join_nat([f.title for f in xfind[:2]]))
    if move:
        out.append(f"\nThe adversary pivoted between systems rather than acting locally: "
                   f"{_join_nat(move)} — evidence of lateral movement using shared "
                   f"credentials or tooling. Treat this as one environment-wide intrusion.")

    # 3. the focal point — most-compromised host gets the spotlight
    if worst['tactics']:
        out.append(f"\n**{worst['host']}** ({worst['sev']}, {worst['n']} finding(s)) is the "
                   f"focal point of the compromise, where activity reached "
                   f"{_join_nat([_TACTIC_SHORT.get(l, l.lower()) for l in worst['tactics'][:5]])}.")

    # 4. reconstructed progression by host — deeper detail for the malicious ones
    out.append("\n**Reconstructed progression:**")
    for p in chrono:
        when = f"`{p['first']}` — " if p['first'] else ""
        if sev.at_least(p['sev'], "high") or p['risk'] >= 60:    # malicious → full prose
            clauses = [f"{_TACTIC_VERB.get(l, l.lower())} "
                       f"({', '.join(sorted(p['tac_map'][l])[:2])})" for l in p['tactics']]
            body = _join_nat(clauses) if clauses else "suspicious activity recorded"
        else:                                                    # lower signal → brief
            body = _join_nat([_TACTIC_SHORT.get(l, l.lower())
                              for l in p['tactics']]) or "lower-severity activity"
        out.append(f"- {when}**{p['host']}** ({p['sev']}): the adversary {body}.")
    out.append("")
    return "\n".join(out)


def _ioc_source_label(graph, ioc):
    """The file/process NAME behind a hash IOC, so an analyst can act on it instead of a
    bare digest. Generic: it follows the graph relationship the hash was matched from, so
    it works for ANY binary — known or custom/unknown — because it keys on the link, not
    on a table of tool names. Returns a short 'name' or None."""
    if (ioc.attrs or {}).get("ioc_kind") != "hash":
        return None
    sn = (ioc.attrs or {}).get("source_name")
    if sn:
        return str(sn).replace("\\", "/").rsplit("/", 1)[-1] or str(sn)
    for r in graph.relationships:
        other = r.src if r.dst == ioc.id else (r.dst if r.src == ioc.id else None)
        if not other:
            continue
        e = graph.entities.get(other)
        if e and e.type in ("process", "file", "binary") and e.label:
            lbl = str(e.label).strip()
            # prefer a basename if the label is a path
            return lbl.replace("\\", "/").rsplit("/", 1)[-1] or lbl
    return None


def _high_confidence_iocs(graph, validations=None):
    """Filter IOCs to those we can stand behind, so the IOC list is genuine indicators
    rather than an inventory of every benign hash on disk. KEEP an indicator only when:
      - validated — cited by a finding the analyst confirmed TRUE POSITIVE ('by us'),
      - detection — cited by any finding (it drove a detection),
      - cross-host — the same artefact appears on 2+ hosts (tool reuse / lateral spread),
      - high-anomaly — independently scored high on its own.
    Everything else (a hash merely seen once, low/zero anomaly) is dropped as noise.
    Returns (list[(ioc, reason)], suppressed_count)."""
    iocs = graph.by_type("ioc")
    cited = set()
    for f in graph.findings:
        cited.update(f.entity_ids or [])
    real_fids = {v.get("finding_id") for v in (validations or [])
                 if v.get("status") == "real"}
    validated = set()
    for f in graph.findings:
        if f.id in real_fids:
            validated.update(f.entity_ids or [])
    kept = []
    for i in iocs:
        if i.id in validated:
            reason = "validated"
        elif "cross_host" in (i.flags or []):
            reason = "cross-host"
        elif i.id in cited:
            reason = "detection"
        elif sev.at_least(i.severity, "high"):
            reason = "high-anomaly"
        else:
            continue
        kept.append((i, reason))
    # validated/detection/cross-host first, then by host spread
    rank = {"validated": 0, "detection": 1, "cross-host": 2, "high-anomaly": 3}
    kept.sort(key=lambda kr: (rank.get(kr[1], 9), -len(_assets_of(kr[0])), kr[0].label))
    return kept, len(iocs) - len(kept)


def report_header(graph, *, window=None, min_severity="informational") -> str:
    """Provenance block: what was examined, over what period, under what filter.

    Every professional DFIR report opens with this and ours did not — it began at
    "## Executive Summary" with no statement of scope, so a reader could not tell
    which hosts were in scope, how much data backed it, or what the filters
    excluded. Without that, "9 hosts, 93 findings" is unfalsifiable: findings
    BELOW the severity floor or outside the window are invisible, and a reader who
    does not know the floor cannot tell absence-of-evidence from evidence-of-
    absence. Timestamps are stamped UTC explicitly for the same reason — a
    forensic timeline whose zone is assumed is a timeline that gets misread.
    """
    from datetime import datetime, timezone
    assets, findings = scope(graph, window=window, min_severity=min_severity)
    sev = _sev_tally(findings)
    ts = [f.ts for f in findings if f.ts]
    span = f"{min(ts)} → {max(ts)}" if ts else "no time-anchored activity"
    # Analysis window and severity floor are deliberately NOT here: they restate
    # the case Configuration rather than describing the evidence, and the
    # narrative's Limitations section already states the floor where it matters
    # (as a caveat on what the report could not see, not as a header field).
    rows = [
        "> **All timestamps are UTC.**",
        "",
        f"| | |",
        f"|---|---|",
        f"| **Report generated** | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} |",
        f"| **Hosts in scope** | {len(assets)} |",
        f"| **Findings** | {len(findings)} "
        f"({sev.get('critical',0)} critical, {sev.get('high',0)} high, "
        f"{sev.get('medium',0)} medium) |",
        f"| **Evidence span** | {span} |",
        f"| **Entities correlated** | {len(graph.entities):,} across {len(graph.relationships):,} links |",
    ]
    return "\n".join(rows) + "\n"


def timeline_md(graph, findings, *, window=None, eff_detail="summary",
                max_groups=None, heading="## Timeline of Events", note=None) -> str:
    """The chronological timeline for ONE scope, as markdown.

    Extracted verbatim from facts_md so a SEGMENTED report can render one timeline
    per phase instead of a single flat list for the whole case -- the operator's
    "the timeline of events should be separate to each timeframe". `findings` is
    already scoped by the caller; `window` re-filters defensively as before.

    `eff_detail` is passed IN, never re-resolved: _resolve_detail() consults the
    scope it is given, so calling it per narrow phase would flip a macro case to
    `explicit` inside every section and blow the report up. `max_groups` budgets
    the collapse cap across phases -- TIMELINE_MAX_GROUPS is per-invocation, so N
    phases would otherwise allow 40xN groups.
    """
    cap = TIMELINE_MAX_GROUPS if max_groups is None else max(1, int(max_groups))
    out = []
    tally = _sev_tally(findings)
    out.append(heading + "\n")
    out.append("_" + (note or (", ".join(f"{tally[lv]} {lv}"
               for lv in reversed(sev.LEVELS) if tally[lv])
               + " — high/critical events in chronological order (host in each entry)"))
               + "._\n")
    tl = sorted((f for f in findings
                 if f.ts and in_window(f.ts, window)
                 and f.kind != "cross_host"                         # in Cross-Host Correlation
                 and not f.title.startswith("Coordinated suspicious activity")  # vacuous rollup
                 and sev.at_least(f.severity, "high")),
                key=lambda f: (f.ts, -sev.rank(f.severity)))
    if not tl:
        out.append("_No time-anchored high/critical activity in window._\n")
    elif eff_detail == "summary":
        # AT SCALE the flat list is the single largest block in the report and most
        # of it is the SAME detection repeating — a senior report states a recurring
        # detection once, with its span and count, not forty times. Collapse on
        # (title, severity); criticals are never collapsed away, only grouped.
        from collections import OrderedDict
        # Finding titles embed the host ("SIGMA: Suspicious Service Path on ALDC02"),
        # so grouping on the raw title collapses NOTHING. Strip the trailing
        # " on <known-host>" so the SAME detection across hosts groups into one row
        # with its host list — which is the whole point of the collapse.
        _labels = {a.label for a in graph.by_type("asset") if a.label}

        def _norm_title(t):
            for lb in _labels:
                if t.endswith(f" on {lb}"):
                    return t[: -(len(lb) + 4)]
            return t

        groups: "OrderedDict[tuple, list]" = OrderedDict()
        for f in tl:
            groups.setdefault((_norm_title(f.title), f.severity,
                               tuple(f.mitre or [])), []).append(f)
        # The cap must NEVER be able to drop a critical: groups are in chronological
        # order, so a plain head-slice silently hid late criticals behind earlier
        # high-severity noise. Keep every critical group, then fill the remaining
        # budget chronologically, then restore chronological order for display.
        _ordered = list(groups.items())
        _crit = [kv for kv in _ordered if kv[0][1] == "critical"]
        _rest = [kv for kv in _ordered if kv[0][1] != "critical"]
        _keep = _crit + _rest[: max(0, cap - len(_crit))]
        _keep.sort(key=lambda kv: min((x.ts for x in kv[1] if x.ts), default=""))
        _omitted = len(_ordered) - len(_keep)
        for (title, sv, mit), fs in _keep:
            ts_all = sorted(x.ts for x in fs if x.ts)
            when = fmt_ts(ts_all[0])
            if len(ts_all) > 1 and ts_all[-1] != ts_all[0]:
                when += f" → {fmt_ts(ts_all[-1])}"
            hosts = sorted({_host_label(graph, a) for f2 in fs for a in (f2.asset_ids or [])})
            hs = (f" · {', '.join(hosts[:4])}" + ("…" if len(hosts) > 4 else "")) if hosts else ""
            mitre = f" `[{', '.join(mit)}]`" if mit else ""
            times = f" · ×{len(fs)}" if len(fs) > 1 else ""
            out.append(f"- `{when}` · **[{sv}]** {title}{mitre}{times}{hs}")
        if _omitted:
            out.append(f"- _… {_omitted} further **non-critical** recurring detection "
                       "group(s) omitted at this altitude — every critical group is "
                       "shown above; narrow the scope for the full timeline._")
        out.append(f"\n_{len(tl)} event(s) collapsed into {len(groups)} recurring "
                   "detection group(s); a repeated detection is stated once with its "
                   f"span and count. All {len(_crit)} critical group(s) are shown._\n")
    else:
        for f in tl:
            mitre = f" `[{', '.join(f.mitre)}]`" if f.mitre else ""
            out.append(f"- `{fmt_ts(f.ts)}` · **[{f.severity}]** {f.title}{mitre}")
            if eff_detail == "explicit":           # real per-event evidence inline
                for ev in _finding_evidence(graph, f,
                                            cap_chars=REPORT_EVIDENCE_CHARS):
                    out.append(f"    - `{ev}`")
    return "\n".join(out)


def facts_md(graph, *, window=None, min_severity="informational", initial_access=None,
             dispositions=None, validations=None, detail="auto", narrated=False,
             timeline_findings=None, timeline_heading=None, timeline_note=None) -> str:
    """DETERMINISTIC report body — Priority Hosts table, cross-host correlation,
    analyst validations, ONE flat chronological timeline, IOC appendix, MITRE,
    recommendations. Appended verbatim to every report; NEVER sent to the LLM.

    Deliberately NOT here (they duplicated each other): a second host-ranking list,
    an Escalation section (the table's Next column says it), per-host detail (the
    single timeline carries it), and phase-split sub-sections."""
    assets, findings = scope(graph, window=window, min_severity=min_severity)
    eff_detail, reason = _resolve_detail(graph, detail, window=window,
                                         min_severity=min_severity)
    out: list[str] = []
    out.append(f"_Report detail: **{eff_detail}** ({reason})._\n")

    # ---- Attack Assessment (infrastructure-wide story from the timeline) ----
    # Suppressed when the model wrote the narrative: it reconstructs the same
    # intrusion the LLM's "Attack Narrative" just told, in weaker prose, directly
    # underneath it. The per-host progression it carried is not lost — it now goes
    # INTO the payload as host_coverage, where it does more good.
    if not narrated:
        aa = _attack_assessment(graph, assets, findings, window=window,
                                initial_access=initial_access)
        if aa:
            out.append(aa)

    # ---- Cross-host correlation (stated ONCE) -------------------------
    xh = [f for f in findings if f.kind == "cross_host"]
    shared_hashes = [e for e in graph.by_type("ioc")
                     if e.attrs.get("ioc_kind") == "hash" and "cross_host" in e.flags]
    if narrated:
        # The LLM writes its own "Cross-Host Correlation" with hashes, direction
        # and reasoning. Emitting this one too produced two sections of the same
        # name in one report, the second strictly weaker. Keep only the fact the
        # bullet list had that the narrative does not reliably state — the shared
        # hash COUNT — and attach it to the IOC appendix that holds them.
        if shared_hashes:
            out.append(f"_{len(shared_hashes)} file hash(es) are shared across hosts "
                       f"(tool reuse / lateral transfer) — listed in the IOC appendix below._\n")
    elif xh or shared_hashes:
        out.append("## Cross-Host Correlation\n")
        from collections import Counter
        for title, n in Counter(f.title for f in xh).items():   # collapse identical titles
            out.append(f"- {title}" + (f" (×{n})" if n > 1 else ""))
        if shared_hashes:
            out.append(f"- {len(shared_hashes)} file hash(es) shared across hosts "
                       f"(tool reuse / lateral transfer) — full hashes in the IOC appendix")
        out.append("")

    # ---- analyst validations (Timeline triage) ------------------------
    av = _analyst_validations_md(graph, dispositions, validations)
    if av:
        out.append(av)

    # ---- chronological timeline — extracted so a SEGMENTED report can render
    # one per phase. It was ~70 lines inline here with no seam, which is why the
    # macro report could only ever carry ONE flat timeline for the whole case.
    # A SEGMENTED report already printed a timeline under every phase, so repeating
    # the whole case here is mostly re-reading: measured at 72% overlap, 29 of 40
    # detections. The caller passes only the findings NO phase covered, which turns
    # a redundant block into the answer to "what is not covered above". A focused
    # report passes nothing and keeps the full timeline -- it has no phases, and this
    # is its primary evidence.
    _tl = findings if timeline_findings is None else timeline_findings
    if _tl or timeline_findings is None:
        out.append(timeline_md(graph, _tl, window=window, eff_detail=eff_detail,
                               heading=timeline_heading or "## Timeline of Events",
                               note=timeline_note))

    # ---- 4. Key Indicators (IOCs) — high-confidence / validated only --------
    kept_iocs, suppressed = _high_confidence_iocs(graph, validations)
    if kept_iocs:
        out.append("## Indicators of Compromise (IOCs)\n")
        out.append("_Only validated or high-confidence indicators are listed; "
                   f"{suppressed} merely-observed artefact(s) were suppressed as noise._\n"
                   if suppressed else
                   "_Validated or high-confidence indicators._\n")
        out.append("| Indicator | Type | Confidence | Hosts | Cross-host |")
        out.append("|---|---|---|---|---|")
        for i, reason in kept_iocs:
            hosts = ", ".join(_host_label(graph, x) for x in _assets_of(i))
            src = _ioc_source_label(graph, i)
            label = f"`{i.label}` ({src})" if src else f"`{i.label}`"
            out.append(f"| {label} | {i.attrs.get('ioc_kind', '?')} | {reason} | {hosts} | "
                       f"{'⚠ YES' if 'cross_host' in i.flags else 'no'} |")
        out.append("")

    # ---- 5. MITRE ATT&CK ----------------------------------------------
    techs: dict[str, list] = {}
    for f in findings:
        for t in f.mitre:
            techs.setdefault(t, []).append(f.title)
    if techs:
        # HONESTY: state the mapping COVERAGE. Most findings carry no technique id,
        # and a bare technique list silently implies the whole case is mapped. A
        # reader must be able to tell "these are the mapped ones" from "this is all
        # that happened" — below a floor the list is a caption, not a section.
        mapped = sum(1 for f in findings if f.mitre)
        pct = (100 * mapped // len(findings)) if findings else 0
        if pct < MITRE_MIN_COVERAGE_PCT:
            out.append(f"_ATT&CK techniques are mapped for only **{mapped} of "
                       f"{len(findings)}** findings ({pct}%) — too sparse for a "
                       "technique matrix; the mapped ones appear inline in the "
                       "timeline above._\n")
            techs = {}
    if techs:
        out.append("## MITRE ATT&CK Mapping\n")
        out.append(f"_Techniques mapped for {sum(1 for f in findings if f.mitre)} of "
                   f"{len(findings)} findings — absence of a technique is not absence "
                   "of activity._\n")
        for t in sorted(techs):
            extra = f" (+{len(techs[t]) - 1} more)" if len(techs[t]) > 1 else ""
            name = _mitre_name(t)
            label = f"{t} — {name}" if name else t          # no dangling '— ' when unknown
            out.append(f"- **{label}** · {techs[t][0]}{extra}")
        out.append("")

    # ---- Identity Risk (focus order) — placed near the bottom -------------
    rt = risk_table_md(graph, window=window, min_severity=min_severity)
    if rt:
        out.append(rt)

    # ---- Recommendations (actionable next steps) ----------------------
    # Suppressed when the model wrote the narrative: its "Priority actions"
    # (Contain now / Investigate next) is the same content, prioritised and
    # case-specific. Two near-identical action lists of equal length in one report
    # made the reader choose which to trust.
    if not narrated:
        out.append(_recommendations_md(graph, findings, assets))

    # ---- Limitations & Assumptions (what this report could NOT see) ----
    out.append(_limitations_md(graph, assets, findings, window=window,
                               min_severity=min_severity, suppressed_iocs=suppressed))

    return "\n".join(out)


def _limitations_md(graph, assets, findings, *, window=None,
                    min_severity="informational", suppressed_iocs=0) -> str:
    """What the report could NOT see. Every professional interim states this: without
    it a reader cannot separate absence-of-evidence from evidence-of-absence, and the
    severity floor / window silently determine everything above. Derived entirely from
    the case's own filters and data — no LLM, so it cannot drift from what actually ran."""
    lines = []
    if min_severity and min_severity != "informational":
        lines.append(f"- Findings **below `{min_severity}`** were excluded from this "
                     "analysis and are not represented above.")
    # A time window only CONSTRAINS the report if it actually clips the evidence. The
    # case's default window is deliberately ~10 years wide (store.create_case) so it
    # excludes nothing; printing "activity between 2016 and 2026 was considered" read as a
    # real 10-year scope, which is misleading. State the TRUE evidence span, and call the
    # window a scope limit only when it genuinely narrows the dated findings.
    _dated = [d for d in (keys.to_utc_dt(f.ts) for f in findings if f.ts) if d]
    _ev_lo, _ev_hi = (min(_dated), max(_dated)) if _dated else (None, None)
    _ws = keys.to_utc_dt(window.get("start")) if window and window.get("start") else None
    _we = keys.to_utc_dt(window.get("end")) if window and window.get("end") else None
    if (_ws and _ev_lo and _ws > _ev_lo) or (_we and _ev_hi and _we < _ev_hi):
        lines.append(f"- Time scope was narrowed to **{window.get('start') or 'open'}** – "
                     f"**{window.get('end') or 'now'}** (UTC); activity outside this window "
                     "is excluded from this report.")
    elif _ev_lo and _ev_hi:
        lines.append(f"- Analysed evidence spans **{_ev_lo.date()}** to **{_ev_hi.date()}** "
                     "(range of dated findings); no narrower time filter was applied.")
    quiet = [a.label for a in assets
             if not any(a.id in (f.asset_ids or []) for f in findings)]
    if quiet:
        lines.append(f"- **{len(quiet)} host(s) in scope produced no findings** "
                     f"({', '.join(sorted(quiet)[:6])}{'…' if len(quiet) > 6 else ''}) — "
                     "this means nothing was detected in what was collected, NOT that "
                     "the host is known-clean.")
    undated = sum(1 for f in findings if not f.ts)
    if undated:
        lines.append(f"- **{undated} finding(s) carry no timestamp** and cannot be "
                     "placed on the timeline; they are excluded from time-based "
                     "conclusions.")
    if suppressed_iocs:
        lines.append(f"- **{suppressed_iocs} observed artefact(s)** were withheld from "
                     "the IOC list as low-confidence noise.")
    lines.append("- Findings derive from the artefacts collected on the hosts in scope. "
                 "Activity that left no artefact — or occurred on a host not collected "
                 "— cannot appear here.")
    lines.append("- Host **role hints are inferred from naming convention** and should "
                 "be confirmed against the asset inventory before being relied on.")
    return "## Limitations & Assumptions\n\n" + "\n".join(lines) + "\n"


def report(graph, *, window=None, min_severity="informational", initial_access=None,
           case_name="Case", dispositions=None, validations=None, detail="auto") -> str:
    """Full deterministic report = narrative prose + deterministic fact tables.
    The real-LLM path (llm_sim) swaps ONLY ``narrative_md`` for an LLM call over
    ``distilled()`` and re-appends ``facts_md`` verbatim."""
    return (narrative_md(graph, window=window, min_severity=min_severity,
                         initial_access=initial_access, case_name=case_name)
            + "\n" + facts_md(graph, window=window, min_severity=min_severity,
                              dispositions=dispositions, validations=validations,
                              initial_access=initial_access, detail=detail))


_MITRE_NAMES = {
    "T1055": "Process Injection", "T1071": "Application Layer Protocol (C2)",
    "T1021": "Remote Services", "T1078": "Valid Accounts",
    "T1543": "Create/Modify System Process", "T1053": "Scheduled Task/Job",
    "T1547": "Boot/Logon Autostart", "T1059": "Command & Scripting Interpreter",
    "T1570": "Lateral Tool Transfer", "T1574": "Hijack Execution Flow",
    "T1003": "OS Credential Dumping", "T1558": "Steal or Forge Kerberos Tickets",
    "T1562": "Impair Defenses", "T1070": "Indicator Removal", "T1105": "Ingress Tool Transfer",
    "T1082": "System Information Discovery", "T1087": "Account Discovery",
    "T1018": "Remote System Discovery", "T1049": "System Network Connections Discovery",
    "T1136": "Create Account", "T1218": "System Binary Proxy Execution",
    "T1548": "Abuse Elevation Control Mechanism", "T1134": "Access Token Manipulation",
    "T1027": "Obfuscated Files or Information", "T1036": "Masquerading",
    "T1112": "Modify Registry", "T1569": "System Services", "T1219": "Remote Access Software",
    "T1560": "Archive Collected Data", "T1048": "Exfiltration Over Alternative Protocol",
    "T1197": "BITS Jobs", "T1553": "Subvert Trust Controls",
    "T1567": "Exfiltration Over Web Service", "T1566": "Phishing",
    # Sub-techniques worth naming in their own right: the parent name alone
    # ("Impair Defenses") loses the part an analyst triages on ("Disable or Modify
    # Tools"). Anything not named here still resolves through its parent below.
    "T1059.001": "PowerShell", "T1562.001": "Disable or Modify Tools",
    "T1543.003": "Windows Service", "T1553.005": "Mark-of-the-Web Bypass",
    "T1567.002": "Exfiltration to Cloud Storage", "T1003.001": "LSASS Memory",
    "T1558.003": "Kerberoasting", "T1547.001": "Registry Run Keys / Startup Folder",
    "T1053.005": "Scheduled Task", "T1218.011": "Rundll32",
    "T1070.001": "Clear Windows Event Logs", "T1021.001": "Remote Desktop Protocol",
    "T1021.002": "SMB/Windows Admin Shares", "T1027.010": "Command Obfuscation",
    "T1574.001": "DLL Search Order Hijacking", "T1036.005": "Match Legitimate Name or Location",
}


def _mitre_name(t: str) -> str:
    """Technique id -> readable name, falling back to the PARENT technique.

    Detections write sub-technique ids ("T1562.001"), but the table was keyed on base
    techniques ("T1562"), so every recovered id rendered as a bare number next to
    curated ones that had names. Resolving the parent means a sub-technique nobody has
    named yet still reads as "T1574.002 — Hijack Execution Flow" instead of a code."""
    return _MITRE_NAMES.get(t) or _MITRE_NAMES.get(t.split(".")[0], "")
