# Cross-Infrastructure Identity Correlation — design (NOT yet implemented)

Status: **design agreed, no code written.** This is the return point to start implementing.

## Problem
A case fuses data from several infrastructures. The SAME person often appears under
different names across them (AWS IAM user `alon`, endpoint account `AlonM`, an email
`AlonM@gmail.com`), and a host is often named after its user (`ALON-PC`). Today the
fusion graph only merges identities on an **exact normalized key** (domain/UPN forms:
`rami@omcdom.com` ↔ `OMCDOM\rami`). There is NO fuzzy matching, so cross-infra
identities and user→host ownership are invisible in the graph, and the report/chat can
only *guess* at them (an ungrounded LLM inference, killed entirely when masking is on).

## Terminology (important — user ≠ machine)
| Concept | Entity type | Example | Meaning |
|---|---|---|---|
| **Identity** | `account` | `alon`, `ADATUMLAB\almogs`, `rami@corp.com` | the **user / principal** |
| **Host / computername** | `asset` | `ALON-PC`, `ALDC02` | the **machine** |

`ALON-PC` is a host, not an identity. So there are **two distinct link types**, never merges:
- **same-identity** (`account`↔`account`): same person across infrastructures.
- **operates** (`account`↔`asset`): a user owns/uses a machine (host name embeds the user).

## Core model: confidence-scored EDGES, never merges
A confirmed link is a reversible, confidence-scored **graph edge** — not a node merge.
Edges are reversible (decline = remove edge), grounded (report/chat cite a real fact),
**survive masking** (edge sits between the two masked pseudonyms), and feed cross-host /
scoring. A destructive merge is out of scope (maybe later, opt-in, for confirmed
same-identity only).

## Infrastructure buckets (decision A = by source, with endpoint unified)
Velociraptor + Memory (VolWeb) + TimeSketch all hang off the SAME Velociraptor
host/client_id → they are the **same machine**, so they collapse into ONE bucket.
- **Endpoint** = Velociraptor + Memory + TimeSketch
- **AWS**
- **Azure**

"Multiple infrastructures" (→ the correlate/choose option turns on) = the case spans
**≥2 of {Endpoint, AWS, Azure}**. A velo-only / memory-only case = one bucket → no
cross-infra choosing (exact host keys already handle within-endpoint dupes). So fuzzy
correlation is effectively **Endpoint ↔ AWS ↔ Azure**.

## The "Identities" tab (UI)
New Case Analysis tab **between Log and Chat**.
- **Always shows** the case's identities (inventory: who, on which hosts, severity) — even
  single-infra.
- **Correlate/choose** (same-identity) enabled only when ≥2 infrastructure buckets present.
- **operates** (user↔host by name) linking may be allowed even single-infra — OPEN.
- Sections: **Pending** (auto candidates, grouped, most-conflicts-first) with
  `Confirm`/`Decline`; **Confirmed** (auto + manual); **`+ Link identities`** manual control
  (pick any two entities, choose type). Auto-detected links sit at the **bottom**, clearly
  labelled "auto-detected — not human," still reversible.
- **Operator-side, ALWAYS real names** (like the mask audit / case log), even with masking on.

## Candidate generation
- Runs **on-demand** when the tab opens (`GET /api/cases/<id>/identities`) — NOT on every
  fuse (keeps fuse fast). Confirmed links are stored and applied on the next fuse.
- Compare `account` labels vs other `account`s AND vs `asset` hostnames.
- **Cross-infra only** (Endpoint/AWS/Azure) for same-identity; within-bucket dupes already
  keyed.
- **Normalize → block → edit-distance** (strip domain, lowercase, drop `$`/`-pc`/`-desktop`;
  bucket by first token; only then fuzzy) so it is NOT O(n²) blind fuzzy on 20k entities.
- **Stopword-filtered** (reuse llm_sim `_MASK_STOPWORDS`): `admin`/`svc`/`backup`/`user`… never
  generate candidates.

## Confidence = corroborating evidence, NOT the name
The name gets you the candidate list; confidence comes from graph facts the two share:
shared **IP**, shared **host**, **time** overlap, **email/domain**, exact-vs-prefix. Show the
**evidence** next to each suggestion ("shares IP 10.0.0.5", "exact email"), not just a number
— DFIR must be able to answer "why are these linked?".

## Auto vs manual (decision B)
**Auto-confirm only when UNAMBIGUOUS:**
- the match is **unique** — `alon` matches exactly ONE candidate and nothing else, OR
- a **100% strong-identifier** match — full email / SID / exact `UPN == DOMAIN\user`.
  (Note: `x@gmail.com` is a *personal* domain — strong but still reviewable.)

**Multiple candidates (`AlonM`/`AlonN`/`AlonT`) → NEVER automatic.** Grouped ambiguous
decision at the TOP ("alon → which of these? pick one / none"), ranked by evidence, default
**unlinked**. Most-conflicts-first = most unresolved candidates first.

## Transitivity (resolved by the uniqueness rule)
A chain auto-extends **only through hops that are themselves unique/100%**. If `alon→AlonM`
(unique) and `AlonM→AlonM@gmail` (100%) → may group into one identity. Any ambiguous hop
stops auto → manual, so an ambiguous guess can never silently poison a cluster.
- OPEN (cosmetic): show connected safe links as one grouped **cluster**, or keep them as
  separate confirmed **pairs**?

## Isolation (hard requirement)
Fully **optional, best-effort, OFF the critical path** — same pattern as KB enrichment /
masking today (wrapped, degrades silently). If the identities pass throws, it's swallowed;
fuse / report / chat continue unaffected. Its data lives in a **separate case-details key**,
so absence/failure is invisible to the rest of Case Analysis.

## Persistence (hard requirement — like timeline validations)
Any **human** decision (confirm / decline / manual link) is **saved in the case and is
NEVER deleted by fusion** — identical to `timeline_validations` and `dispositions` today:
it lives in a case-details key, and every `fuse_case` **re-applies** it to the freshly
built graph. Re-fusing, adding a run, or reopening the case must not lose or reset a
validated link. Declined stays declined (never resurfaces as a pending suggestion);
confirmed/manual stays confirmed.

Only **auto-detected** links (not human) are recomputed each time: an auto-link is
re-derived on demand and, if its evidence no longer holds after new data, it drops
quietly with a log line — but a human decision on it (e.g. the analyst declined an auto
link) is itself persisted and wins. Every link carries a **stable id** so decisions bind
across re-fuses.

## Reuse existing plumbing
Model on the **timeline-validation / disposition** workflow (`validate_timeline`,
`generate_disposition_checklist` → `decide_checklist_item` → stored in case details →
re-applied on `fuse_case`): the same validate → persist → survive-refuse loop. Audit
every auto-link and human decision via `log_case_event`.

## Edge cases to honour
- **Service/role/shared accounts** (`svc-*`, `admin`, `DomainAdmins`) — non-personal; exclude
  from same-identity correlation (else infinite false conflicts).
- **One-to-many**: *operates* one-to-many (a user with laptop+desktop) is LEGITIMATE, not a
  conflict; *same-identity* one-to-many IS a conflict.
- **Persistence across re-fuse**: decisions stick (declined stays declined, never resurfaces;
  confirmed stays); links need **stable ids**; an auto-link that stops holding drops quietly
  with a log line (never silently mislinks).
- **Scope = within the case** only (cross-case identity = the KB layer, out of scope).
- **Masking**: tab always shows truth; confirmed edge still flows into masked reports as
  pseudonym↔pseudonym.

## Payoff
Once confirmed, the link is a **grounded graph fact**: report states "AWS user `alon` operates
`ALON-PC` (analyst-confirmed)", chat pivots across it, it counts toward cross-host findings —
all grounded, analyst-verifiable, surviving masking.

## Open decisions before build
1. Cosmetic: connected safe links shown as one **cluster** vs separate **pairs**.
2. Allow **operates** (user↔host) linking even in single-infra cases?
3. Do confirmed links feed **risk scoring / cross-host findings** from day one, or display-only first?

## Likely files when implementing
`services/fusion/correlate.py` (candidate pass), `services/fusion/store.py`
(confirm/decline/persist + apply-on-fuse, mirror dispositions), `routes/case_routes.py`
(`/identities` endpoints), `modules/nginx/html/cases.html` (Identities tab),
reuse `services/fusion/llm_sim.py:_MASK_STOPWORDS`.
