"""A case's mode: IR (incident response, the default) or Proactive.

IR reads every piece of evidence as possible compromise -- right when something
has happened. Proactive is a routine check of an environment presumed healthy:
it flags only what is worth someone's time, and says calmly why. Asked for
2026-11-22. A case from before then, or a bundle from an older appliance, has no
mode and is IR.

What Proactive changes (each place reads it from here):
  - scores: every finding below critical is one level lower (correlate.assemble),
    so host risk follows; critical is never lowered
  - the AI: report and chat get PROACTIVE_RULE as steering (store), Investigate
    too; the decision model asks with DECISION_NOTE and needs more certainty
    before it marks a finding malicious
  - the report's title (titled)
"""

IR, PROACTIVE = "ir", "proactive"

PROACTIVE_RULE = (
    "CASE MODE: PROACTIVE REVIEW. This is a routine check of an environment presumed to be "
    "operating normally, not an incident response. Read the evidence calmly and in "
    "proportion: do not assume compromise, do not use alarming language, and do not treat "
    "ordinary administration, software installs and updates, security or management "
    "tools' own activity, or people's routine work as attack activity. Raise a concern only "
    "when the evidence is strong and specific enough to be worth someone's time; anything "
    "critical is still said plainly. For every item you raise, stay rational and balanced "
    "and give all three: why it might be malicious, why it might be a false positive or "
    "normal activity, and exactly what to check to confirm or rule it out. Findings below "
    "critical were already rated one level lower for this review; keep every severity and "
    "risk at or below what the findings give, and call the environment healthy when "
    "nothing stands out.")

DECISION_NOTE = (
    " This is a PROACTIVE review of an environment presumed healthy, not an incident: rate "
    "it malicious only on strong, specific evidence. Routine administration, software "
    "updates and security tools' own activity are normal.")

TITLE_IR = "# Incident Case Report — "
TITLE_PROACTIVE = "# Proactive Security Review — "


def clean(v) -> str:
    """A posted value: 'proactive', or IR for anything else."""
    return PROACTIVE if str(v or "").strip().lower() == PROACTIVE else IR


def of(d) -> str:
    """The case's mode; IR when it has none (old cases and bundles)."""
    return clean((d or {}).get("case_mode") if isinstance(d, dict) else None)


def steering(d):
    """What the report and chat are steered with: Proactive's rule, then the
    operator's own Steering (master prompt). None when there is neither."""
    own = ((d or {}).get("master_prompt") or "").strip()
    rule = PROACTIVE_RULE if of(d) == PROACTIVE else ""
    return "\n\n".join(x for x in (rule, own) if x) or None


def titled(md, d) -> str:
    """The report under its mode's title (render and llm_sim write the IR one)."""
    if of(d) == PROACTIVE and (md or "").startswith(TITLE_IR):
        return TITLE_PROACTIVE + md[len(TITLE_IR):]
    return md
