# Edge cases (deterministic)

| Test | What | Result | |
|---|---|---|:--:|
| **M1** | masking at corpus scale — any real host/account leaking? | hosts=8, accounts=1, round_trip_ok=False | ✅ |
| **X1** | clock skew — hosts 6h apart | rows=2, order=['SKEW-B', 'SKEW-A'], chronological_by_stamp=True, both_hosts_present=True | ✅ |
| **X2** | contradictory evidence — conflicting attrs kept? | process_entities=1, kept_both_values=True, conflict_flagged=True | ✅ |
| **X3** | hostile strings — 200 KB cmdline, RTL, NUL, emoji | entities=3, payload_chars=719, report_chars=1297, payload_bounded=True | ✅ |
| **X4** | single-event case — smallest possible report | findings=1, altitude=focused, report_chars=1411, has_timeline=True, has_limitations=True | ✅ |
