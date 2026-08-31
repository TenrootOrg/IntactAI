# Campaign BACKLOG — what to fix / implement

Ranked findings from the fusion + agentic test campaign (Tracks A/B/C, deterministic + at-scale). Each links a repro; action is the proposed fix or feature.

**Quantified at scale (Track B, 100 model runs):** turn-1 give-up (A1) **4.0%**, fabricated-host **2.0%**.

## FIX (defects)

| Sev | ID | Track | Finding | Proposed action |
|---|---|---|---|---|
| medium | D-hash-case_1788080164853__S0-baseline.md | D | Ungrounded sha256 in case_1788080164853__S0-baseline.md | — |

## IMPLEMENT (capability gaps)

| Sev | ID | Track | Finding | Proposed action |
|---|---|---|---|---|
| medium | A5 | prior-eval | No temperature/seed control on Codex -> irreducible run-to-run variance | Add bounded self-consistency / retry on the loop (Codex has no temperature knob); the min-step guard (A1) also cuts variance impact. |
| medium | A6 | prior-eval | Masking strips hostname role hints (DC/CA), degrading tier-zero priority | Pass a role hint (DC/CA/MECM) through the masked tool output so the model keeps tier-zero priority when hostnames are pseudonymized. |
| low | A8 | prior-eval | Masking is best-effort: an identifier only inside a raw evidence row can leak unmasked | Extend the mask sweep to raw-row values before they reach the model (or redact unknown identifier-shaped tokens in tool output). |

## Repros

- **A5** (medium): same question yields 0 vs 2+ tool steps across repeats (Track B)  
  Codex subscription CLI exposes no temperature/seed; A4 confirmed runtime==eval transport (codex-subscription/gpt-5.6-sol), so the live 0-step is genuine sampling variance. Quantified by Track B give-up rate.
- **A6** (medium): see investigate_v1_vs_v2.md cross-host/timeline rows  
  v1-vs-v2 judged eval: v2 scored 11 (cross-host) and 13 (timeline) vs v1's 17/20 because pseudonymizing ALDC02->Hostname7 destroys the 'domain controller' signal carried by the name. Privacy win, correctness regression on tier-zero questions.
- **D-hash-case_1788080164853__S0-baseline.md** (medium): ground_check on case_1788080164853__S0-baseline.md  
  hashes not in payload: ['58189cbd4e6dc0c7d8e66b6a6f75652fc9f4afc7ce0eba7d67d8c3feb0d5381f']
- **A8** (low): raw row contains a hostname absent from graph entities  
  _build_mask_mapping is graph-derived; a value present only in a raw row (not an entity) may not be in the mapping and reaches the provider. Acknowledged in investigate.py docstring.
