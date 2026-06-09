"""Prompts + section layout for the Engagement Report builder.

Kept in a separate file so the operator can tune the wording without
touching the orchestration logic in builder.py."""

# How much of each source report to include in the synthesis LLM
# prompt's evidence block. Each source gets its own 5 k-char slot;
# the full text still ends up verbatim in the final document's
# Appendix A, so trimming here only affects what the LLM sees while
# writing the executive layer.
SOURCE_EVIDENCE_CHAR_BUDGET = 5_000

# Maximum body length (per source) inlined under §5/§6/§7 in the
# main document body. Anything longer is truncated with a pointer to
# Appendix A where the full text lives.
SOURCE_INLINE_CHAR_BUDGET = 10_000

# Canonical section names, in the order they should appear in the
# assembled report. Each automation_type maps to exactly one of
# these. "Endpoints" covers Velociraptor-collected agentic runs
# (workstations + servers including DCs). Any non-canonical label
# falls into "Other" at the end.
CANONICAL_SECTIONS = ("Endpoints", "AWS", "Azure", "Vulnerabilities", "Other")


ENGAGEMENT_SYSTEM_PROMPT = """You are a senior DFIR consultant writing the executive layer of an
INCIDENT RESPONSE ENGAGEMENT REPORT for a customer. This is the
customer-facing deliverable a professional IR firm (Mandiant /
CrowdStrike Services / Stroz / Unit 42) would ship at the end of an
engagement: a multi-environment forensic write-up suitable for both
executive leadership AND the customer's technical responders.

You will be given:
- The engagement name and any operator-supplied context notes.
- For each source workflow that was included: its environment label
  (Endpoints / AWS / Azure / Other), a condensed extract of its
  individual report, and any available metadata (hosts, accounts,
  scan windows).

STRICT FORMATTING RULES (the assembler trusts you to follow them):

1. Do NOT emit ANY level-1 heading (`# `). The cover page has the
   document's only H1. Do not write
   `# INCIDENT RESPONSE ENGAGEMENT REPORT` or anything similar.
2. Use the EXACT numbered headings shown below, including the
   `## N. ` prefix. Do not omit the number.
3. Inside each section, prefer plain paragraphs. Bulleted lists are
   only used where called out explicitly below (asset inventory,
   recommendations, timeline table).
4. Emit the literal separator line `<!-- BREAK -->` on its own line
   between §5 Key Findings and §10 Recommended Next Steps. The
   assembler uses it to interleave the per-environment sections.

WRITE THESE FIVE SECTIONS, IN ORDER:

## 1. Executive Summary
Two to three short paragraphs for non-technical leadership.
- Para 1: what happened — the headline story in plain language.
- Para 2: business impact + current state of the incident
  (contained / under investigation / resolved) + overall risk
  level (CRITICAL / HIGH / MEDIUM / LOW in bold).
- Para 3 (optional): confidence in the findings and notable
  caveats / scope limitations.

## 2. Engagement Scope & Methodology
First paragraph: narrative scope statement — environments touched,
hosts / accounts / tenants in scope, the time window covered,
overall objective of the engagement.

Then a bulleted **Assets in Scope** list, one bullet per major
asset (IAM user, S3 bucket, tenant, hostname, etc.), grouped by
environment.

Then a bulleted **Data Sources & Methodology** list, one bullet
per data source — what it is, what we collected from it, and (one
short clause) what kind of attacker activity it surfaces. e.g.
- AWS CloudTrail — API call audit log; surfaces console logins,
  IAM changes, persistence creation, defense evasion.

## 3. Attack Narrative
One to two flowing paragraphs (no bullets) telling the story of
what the adversary did, in plain English, in chronological order.
This is the human-readable counterpart to §4 Timeline. Frame the
attacker's intent ("the adversary appears to have prioritised
persistence over exfiltration"), call out cross-environment
correlation explicitly, and label residual uncertainty honestly.
Do not invent attribution. Do not pretend to know motive.

## 4. Timeline of Events
A markdown table with one row per dated event, in chronological
order. Columns:

| Timestamp (UTC) | Environment | Actor / Source | Event | Detection / Source Workflow |

Use ISO-style timestamps (YYYY-MM-DD HH:MM:SS UTC). When seconds
aren't available, write `YYYY-MM-DD HH:MM UTC`. If two events
happened at the same time across environments, list them on
adjacent rows.

## 5. Key Findings
Render each finding as a structured BLOCK so the customer can
scan / grep them. Order by severity (Critical → High → Medium →
Low). Numbering: `F-1`, `F-2`, `F-3`, ... Format EXACTLY:

### F-N: <one-line title>
- **Severity:** Critical / High / Medium / Low
- **Confidence:** High / Medium / Low
- **Environment:** Endpoints / AWS / Azure / Multiple
- **Detected:** ISO timestamp (or "-" when undated)
- **Source:** `<source workflow run_id>` · `<detection / SIGMA rule
  name or section>`

**Description.** One or two sentences. What we saw.

**Evidence.** Bullet list of the concrete artifacts that support
the finding — file names, log event IDs, IP addresses, SIGMA rule
names, account names, timestamps. Be specific.

**Impact.** One short sentence. What the adversary gains or what
risk this creates for the customer.

**Recommendation.** One short sentence. The remediation that, if
done today, would close this finding. Do NOT add a cross-reference
line — §10 will cite each finding from the action side instead, so
the direction stays one-way.

Then a blank line, then the next finding block.

After §5 emit `<!-- BREAK -->` on its own line.

THEN WRITE THESE TWO SECTIONS. Use the literal headings shown —
the assembler will renumber them to whatever ordinals fit (the
per-environment sections, IOCs, and Containment Actions Taken
occupy ordinals in between, so the actual numbers you'll see in
the final document may be §11 / §12 or §12 / §13):

## Recommended Next Steps
Three subsections, each a bulleted list of concrete actions. Each
action starts with a bold action label, then a one-sentence
description, then `*(Responds to: F-N, F-M)*` cross-referring to
the findings it answers.

- **Immediate (next 24 hours)** — actions that should happen today.
- **Short-term (next week)** — investigative or remediation work
  that benefits from a few days' planning.
- **Long-term (next quarter)** — structural / policy / monitoring
  improvements suggested by the incident.

## MITRE ATT&CK Mapping
A markdown table mapping the engagement's findings to ATT&CK
techniques:

| Tactic | Technique | ID | Evidence (finding + source) |

Only emit rows for techniques you can directly support from
evidence in the source reports. Do not list techniques that
sound plausible but aren't actually demonstrated. If no source
reports surface MITRE-mappable activity, omit this section
entirely.

OVERALL DISCIPLINE
- Stay grounded in the source material. Do not invent details,
  IPs, account names, timestamps, or attribution claims that
  aren't in the inputs.
- **NEVER use placeholders like `XX`, `YY`, or `??` in a
  timestamp.** Write what you know or drop the precision (use
  minute-granularity instead of second-granularity).
- **DATE / DURATION ARITHMETIC: double-check it.** If the
  earliest event in your evidence is 2026-04-29 and the latest
  is 2026-05-18, the investigation window is roughly three weeks,
  not "May 3 to May 18". If a data source's coverage spans
  August 2023 to May 2026, that is roughly 33 *months*, not
  *days*. Whenever you state a duration, compute it from the
  actual dates you cited above — don't guess.
- If the source reports disagree or have gaps, note that in §1
  or §3.
- **NEVER speculate on attribution or motive.** Phrases like
  "single threat actor", "coordinated team with deep knowledge",
  "nation-state", "insider with malicious intent" are off-limits
  unless a source report explicitly makes that attribution. You
  can describe the behaviour pattern ("the activity is
  consistent with a sophisticated post-exploitation playbook")
  without attributing it to a specific actor. If you don't have
  attribution evidence, say so plainly: "the attribution of this
  activity is undetermined from the available evidence".
- Word budget: aim for ~2500 words total across §1-§5, ~400 words
  for §10, table-only for §11.
- Tone: professional, calm, factual. This is what the customer's
  CIO is going to read in their boardroom.
"""


def audience_language_directive(audience: str = 'both', language: str = 'en') -> str:
    """Return a short directive block to append to ENGAGEMENT_SYSTEM_PROMPT
    so the LLM tailors the executive layer to the chosen audience +
    language. Both controls are optional — defaults preserve the
    previous behaviour (technical + executive bilingually-readable
    English).

    audience: 'technical' | 'executive' | 'both' (default).
    language: ISO short code — 'en' (default) or 'he' for Hebrew.
    """
    lines = []
    aud = (audience or 'both').lower()
    if aud == 'executive':
        lines.append(
            "## AUDIENCE: Executive\n"
            "Write strictly for a non-technical executive audience (CIO, "
            "CISO, board). Lead with business impact, risk posture, and "
            "recommended decisions. Avoid rule names, log field "
            "references, and per-artefact technicalia inside §1-§4. "
            "Save the deep technical detail for the verbatim source "
            "appendices that follow."
        )
    elif aud == 'technical':
        lines.append(
            "## AUDIENCE: Technical (DFIR / SOC)\n"
            "Write for a technical audience already fluent in DFIR. "
            "Cite rule IDs, log sources, host/principal identifiers, "
            "ATT&CK technique numbers, and exact timestamps liberally. "
            "Keep §1 brief; spend the budget on §3 (Attack Narrative) "
            "and §5 (Key Findings)."
        )
    else:
        lines.append(
            "## AUDIENCE: Mixed (Executive + Technical)\n"
            "Default audience — open each section with a one-paragraph "
            "executive summary, then expand into technical detail. "
            "The same document needs to serve both the CIO and the "
            "responding SOC."
        )

    lang = (language or 'en').lower()
    if lang in ('he', 'heb', 'hebrew'):
        lines.append(
            "\n## LANGUAGE: Hebrew\n"
            "Write the ENTIRE deliverable in modern professional Hebrew. "
            "Technical terms (CVE-IDs, ATT&CK technique IDs, rule names, "
            "log field names, hostnames, IPs, hashes) stay in their "
            "original English/Latin form — do not transliterate them. "
            "Section headings, narrative prose, table headers, and "
            "recommendations are all in Hebrew."
        )
    # English is the default — no extra directive needed.

    return "\n\n".join(lines)


def cover_block(name, generated_at, sources, tlp='AMBER', version=1, customer_name='', severity_summary=''):
    """Return the markdown cover block that opens the assembled
    report. Layered like a professional IR firm deliverable:

      - Document title + classification badge (TLP marker)
      - Document metadata table (version, prepared by, dates)
      - Sources-included table (auto-detected from selected runs)
      - Document History — one row per build / re-run

    `sources` is a list of `{'run_id', 'name', 'section',
    'automation_type'}` so we can render the workflows-included
    table.

    `tlp` defaults to AMBER (sensitive, recipient may share within
    their organisation on a need-to-know basis) — the safe default
    for IR deliverables. Set to RED for tighter restrictions or
    GREEN/WHITE for broader.

    `version` is the report revision; bumps on interactive re-run
    by the chat-driven master-prompt cycle.

    `customer_name`, when set, is rendered into a "Prepared for: <name>"
    line on the cover. When blank the line is omitted (back-compat with
    runs dispatched before the field existed).
    """
    tlp_color = {
        'RED': '🟥',
        'AMBER': '🟧',
        'AMBER+STRICT': '🟧',
        'GREEN': '🟩',
        'WHITE': '⬜',
        'CLEAR': '⬜',
    }.get(str(tlp or '').upper(), '🟧')
    lines = [
        f"# Engagement Report — {name}",
        "",
        f"**Classification:** `TLP:{tlp.upper()}` {tlp_color}  ·  "
        f"**Version:** v{version}  ·  "
        f"**Generated:** {generated_at}",
        "",
    ]
    if (customer_name or '').strip():
        lines.append(f"**Prepared for:** {customer_name.strip()}")
        lines.append("")
    if (severity_summary or '').strip():
        lines.append(f"**Severity Summary:** {severity_summary.strip()}")
        lines.append("")
    lines += [
        "Prepared by Intact.AI",
        "",
        "---",
        "",
        "## Workflows included",
        "",
        "| Environment | Source workflow | Source name |",
        "|---|---|---|",
    ]
    pipe_escape = "\\|"
    for src in sources:
        name_safe = (src.get('name') or '').replace('|', pipe_escape)
        lines.append(
            f"| {src.get('section', '?')} | `{src.get('run_id', '?')}` | "
            f"{name_safe} |"
        )
    lines.append("")
    lines.append("## Document History")
    lines.append("")
    lines.append("| Version | Date | Author | Summary |")
    lines.append("|---|---|---|---|")
    lines.append(
        f"| v{version} | {generated_at} | Intact.AI engagement builder | "
        f"{'Initial build' if version == 1 else f'Revision v{version} — applied operator chat corrections'} |"
    )
    lines.append("")
    return "\n".join(lines)


def section_heading(section_name, ordinal):
    """Heading line for one of the per-environment sections (§5–§7
    in the canonical layout, plus any "Other" catch-all)."""
    return f"## {ordinal}. {section_name}\n"


def ioc_table_header():
    return (
        "| Type | Indicator | Sources |\n"
        "|---|---|---|\n"
    )


def appendix_heading():
    return (
        "\n---\n\n"
        "## Appendix A — Source Reports (verbatim)\n"
        "\n"
        "*Each source workflow's full report as it was generated, "
        "preserved for the engagement's record.*\n"
    )
