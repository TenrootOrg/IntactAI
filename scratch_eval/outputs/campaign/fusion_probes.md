# Track C — Fusion hazard probes

3 findings / 4 probes. Deterministic.

| Sev | ID | Status | Finding | Repro |
|---|---|---|---|---|
| medium | F2 | FINDING | schema._wider string-compares timestamps (breaks on mixed Z/fractional/epoch) | schema._wider('2026-...T12:00:00Z','2026-...T12:00:00.5Z', want_min=False) |
| low | F2b | FINDING | _wm_new_activity string-compares the watermark time half | _wm_new_activity(old='1|...00Z', new fractional ts) |
| low | F3 | FINDING | TRIGGER_IDENTITY is a dead constant (identity edits apply only next fuse) | grep TRIGGER_IDENTITY in store.py — defined, never emitted |
| info | F_pid | PASS | process identity falls back to image name when createtime missing | keys.process_id with createtime='?' |

## Detail

- **[medium] F2 — schema._wider string-compares timestamps (breaks on mixed Z/fractional/epoch)**  
  mismatches vs to_utc_dt ordering: [('2026-06-16T12:00:00Z', '2026-06-16T12:00:00.500Z', 'max', '2026-06-16T12:00:00Z', '2026-06-16T12:00:00.500Z')]
- **[low] F2b — _wm_new_activity string-compares the watermark time half**  
  same string-compare class as F2; a fractional-second-newer occurrence may not re-open a stale disposition. signature=(stored, current) -> 'bool'
- **[low] F3 — TRIGGER_IDENTITY is a dead constant (identity edits apply only next fuse)**  
  defined=True passed_as_trigger=False occurrences=1 — identity mutations persist to identity_links and take effect on the following fuse, not immediately.
