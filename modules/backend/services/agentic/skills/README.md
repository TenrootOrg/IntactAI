# Agentic DFIR skills

Markdown files in this directory are loaded once at backend boot by
[`services/agentic/skills.py`](../skills.py) and injected into the analyzer's
system prompt on a per-request basis (selected by artifact name + MITRE ATT&CK
techniques).

## Layout

```
skills/
├── README.md         <- this file
├── LICENSE           <- Apache-2.0, applies to bundled skills
├── NOTICE            <- attribution to upstream
├── INDEX.md          <- one-line summary per skill (regen-able)
└── dfir/
    └── *.md          <- one skill per file, frontmatter + body
```

## Skill file format

Each `*.md` is in the Anthropic Skills format:

```markdown
---
name: hunting-for-process-injection-techniques
description: |
  Detects process injection techniques (DLL injection, process hollowing, ...)
mitre_attack: [T1055]
tags: [process-injection, defense-evasion]
---

# Body content (markdown)
```

Required frontmatter keys:
- `name` — unique slug, used as the index key
- `description` — short summary used by the selector for keyword scoring

Optional frontmatter keys used by the selector:
- `mitre_attack` — list of ATT&CK technique IDs (highest weight in scoring)
- `tags` — list of free-form tags

## Adding a new skill

1. Drop a `*.md` file under `dfir/` (or any subdir — loader walks recursively).
2. Body must be under `SKILL_BODY_HARD_CAP` tokens (default 8000); files over
   the soft cap (5000) log a warning but still load.
3. Restart the backend — the index is loaded once at boot, not hot-reloaded.
4. Verify with the smoke-test snippet in [`skills.py`](../skills.py).

## Removing or updating an upstream skill

The bundled skills are copied verbatim from
[mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills).
To update a skill, re-copy the upstream `SKILL.md` over the corresponding file
here. Do not edit the bundled skills in place — diverging from upstream makes
future syncs hard.

## Selection

`services.agentic.skills.select_skills(artifact_name, mitre_techniques)` returns
the top-K skill names ranked by:

| Signal | Weight |
|---|---|
| MITRE ATT&CK ID exact match | 5 per ID |
| Tag word in artifact-name tokens | 2 per tag word |
| Artifact-name token in description | 1 per token |

If no skill clears `SKILL_MIN_SCORE` (default 1), no skill is injected and the
analyzer falls back to the base prompt unchanged.

## Token budget

`SKILL_DEFAULT_TOP_K = 1` — at most one skill per analysis. Average bundled
skill is ~3K tokens; total system prompt remains ~3.7K tokens (vs. ~700 tokens
without skills). This is well within every supported provider's context window.
