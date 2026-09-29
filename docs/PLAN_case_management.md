# Plan — Case Analysis replaces IRIS for one analyst

Goal: an analyst works a case start to finish in Case Analysis. Rule for every
item: the smallest version that works, built on what already exists, one commit
per item with its tests. Nothing here acts on the environment by itself.

Order: 0 → 1 → 2 → 5 → 4 → 6 → 9 (9 needs a choice first).

---

## 0. Bug — Jev's "not reviewed yet" ignores part verdicts (found 2026-09-29)

The Analysis banner listed Mimikatz, PowerShell Web Request and Defender as
"look malicious and are not reviewed yet" although every part of them was judged.
`jev.unreviewed_notice` counts only row-level verdicts.

- A row counts as reviewed when it has its own verdict **or** any of its parts has
  one (same rule as `render.row_verdict`).
- Test: a notice row whose parts are judged disappears from the banner.

## 1. A note on a verdict — simple

The backend already saves `notes` with each Timeline verdict; nothing shows or
sends them.

- One small "note" link per row / part → one text box, saved with the verdict
  (existing `/timeline/validate`, `notes` field). One note per verdict, no threads.
- The row shows the note in grey after its tags (the markup for it exists).
- The report's Analyst Validations lists "— note"; the chat already receives notes.
- Test: a note saved on a part reaches the row, the report section and the chat context.

## 2. Case details

- Fields: **status** (Open / Contained / Closed), **severity** (Low → Critical),
  **owner** (free text), **description** (a few lines), and **rename**.
- One endpoint (`PATCH /api/cases/<id>`), stored in the case details.
- Shown in the Case Management list (status + severity chips) and the Case
  Analysis header; edited in Configuration.
- Labels only: a Closed case is not locked or hidden — nothing changes behaviour.
- The description and status go into the report and chat context.
- Test: fields save, survive a re-fuse and a case export/import.

## 5. Host status, tied to Velociraptor isolation

- On the Risk tab, per host: **Not set / Compromised / Isolated / Reimaged / Clean**
  (the analyst's choice; mirrors the Identities verdict).
- **Velociraptor:** if the host's client carries the quarantine label that
  Velociraptor's `Windows.Remediation.Quarantine` sets, show
  "isolated in Velociraptor" next to it (read-only). Verify the exact label on
  the box first. We only READ it — never isolate or release from here.
- Host status goes into the report ("Containment") and the chat.
- Test: status saves; a client with the label shows the badge; no label → nothing.

## 4. Next steps (tasks) — my recommendation, simple

- A **Next steps** list on the Analysis tab: each item is text + done / not done
  + an optional note. No assignees or due dates (single user).
- Filled from the report's "Recommended Next Steps" when a report is written, plus
  "+ Add". Regenerating adds new items only — never removes or reopens yours.
- Done and open items go into the report and chat ("already done: …").
- Test: regenerate twice → no duplicates; a done item stays done.

## 6. Case files and evidence links

**6a. Files.** Attach screenshots, emails, documents to the case.
- Upload through the existing resumable upload (new purpose `case_file`), stored
  per case; list shows name, size, SHA-256, when, note; download; delete (logged).
- File contents are never sent to the model.
- Included in the case export bundle (hashes already verified on import).

**6b. Links back to Velociraptor.** In the finding detail drawer, each occurrence
already shows its locator (e.g. `Windows.Hayabusa.Rules/row=515`).
- Add a link that opens that collection in Velociraptor (client + flow +
  artifact), and for an uploaded collection, which file and row it came from —
  so the analyst can pull the full evidence from Velociraptor.
- **Hit list:** under the full example, each hit of the row — its time and command
  line / key field (first ~200 chars), capped at ~20 — so "4 hits" can be compared
  without leaving the page (asked 2026-09-29: are the 4 the same thing?).
- "Pin as evidence": saves the occurrence (its fields + locator + link, SHA-256
  of the row) to the case's evidence list next to 6a's files.
- **Links are never sent to the model** — stripped from report and chat payloads.
- Test: link built for a live-client run and for an upload; payload to the model
  contains no link.

## 9. Report types — research done, you choose

DFIR engagements usually produce reports at stages (NIST SP 800-61, SANS):

| Report | When | What it holds |
|---|---|---|
| **Flash / Initial** | first hours | what is known, affected hosts so far, immediate containment, when the next update comes |
| **Interim / Status** | daily or weekly while the case is open | progress since last report, timeline so far, containment status (item 5), open questions, next steps (item 4) |
| **Final** | at closure | full: executive summary, scope, timeline, root cause / initial access, impact, IOCs, remediation, recommendations |
| **Lessons learned** | after closure | what worked, gaps, improvements to tooling and process |
| Specialised | when required | regulatory / breach notification (e.g. GDPR 72 h), forensic examination report for legal use (chain of custody) |

Suggestion: a **report stage** choice — Flash / Interim / Final (Lessons learned
later) — next to the existing audience choice (Executive / Technical / Both).
Each stage is a different section list and length; the case status (item 2)
proposes the default (Open → Interim, Closed → Final). Each generated report is
kept with its stage and date, so an Interim does not overwrite the Final.
**Built 2026-09-29:** Flash / Interim / Final with a report history (view, PDF / HTML / MD, delete). History does not travel in case export/import yet.

---

## Cancelled — and why

| Item | Decision |
|---|---|
| 1. A note on a verdict | Built as step 2, then reverted (55cca3ba) — not wanted now. |
| 4. Next steps checklist | Built as step 5, then reverted — not wanted. |
| 6b / step 7. Velociraptor links, hit list, "Pin as evidence" | Not needed (decided 2026-09-29). |
| 3. IOC tab (add/edit, CSV / STIX / MISP export) | Not needed. |
| 7. Who-did-what on every action, a log that cannot be cleared | Multi-user does not exist yet; leave it until it does. |
| 8. Search across cases | Cases are deliberately separate; hunts and workflows from another case can be pulled in when needed. |
| 9 (as proposed). DOCX export | Left for now; replaced by report types (above). |
| 10. Multiple users with roles | Not in this version — too large for now; a later version. |
