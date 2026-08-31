# Evidence-locator resolution audit (deterministic)

Every finding's `EvidenceRef` locator resolved against the telemetry the graph was built from, and checked that the row belongs to the finding's host. An off-by-one here would silently corrupt every drill-down.

- locators checked: **78**
- resolved to a real row: **78**
- row host matches the finding: **78/78**
- out-of-range index: **0**
- wrong host: **0**
- unresolvable: **0**

**✅ PASS — every locator resolves to the correct row**
