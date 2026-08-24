# Case bundle contract

A case bundle moves one investigation from the appliance that collected it to
the appliance that will finish it — usually across an air gap, on removable
media, and usually to a **newer release** than the one that wrote it.

That last point is the contract. This document is what a future release has to
honour so a bundle written today still imports years from now. It is deliberately
short: the fewer promises, the easier they are to keep.

The implementation is `case_bundle.py`; this file is the part that outlives it.

---

## 1. Identity

Every bundle is a ZIP whose `manifest.json` declares:

```json
{"kind": "intact_case_export", "schema": 2, ...}
```

* `kind` never changes. A file that does not carry it is not a case bundle.
* `schema` is an integer describing the LAYOUT below.

## 2. The promise

A release MUST:

1. **Import every bundle whose `schema` is ≤ its own `MAX_SUPPORTED_SCHEMA`.**
   Not "attempt to" — a schema-2 bundle must still import in 2030.
2. **Refuse a newer bundle with an explanation, never a stack trace:**
   > This bundle was exported by a newer Intact release (bundle schema N; this
   > appliance supports up to M). Import it on an appliance at least as new as
   > the exporter.
3. **Require nothing that section 3 does not guarantee.** Read every field with
   a default (`d.get(...) or ...`), the way `normalize_modules` and the tolerant
   `schema_version` read already do. A case exported before a feature existed
   simply lacks its keys; that is normal, not corrupt.
4. **Ignore what it does not recognise** — unknown manifest keys, unknown ZIP
   members. A newer exporter is allowed to add both.
5. **Never reuse the source appliance's run ids.** See section 5.
6. **Verify every listed file's checksum before writing anything**, and extract
   only files the manifest lists (section 4).

Adding an optional key or an optional file does **not** bump `schema`. Only a
change to the layout or the meaning of what is already there does — and a bump
means every older release correctly refuses the bundle under promise 2, so bump
sparingly.

## 3. Layout — schema 2

```
manifest.json                              (required)
case.json                                  (required)  the case's workflow row
graph.json                                 (optional)  the fused graph
runs/<run_id>.json                         (0..n)      member run rows + baseline rows
payloads/<run_id>/raw_results.json         (0..n)      collected rows
payloads/<run_id>/memory_payload.json      (0..n)      memory plugins + YARA hits
aws_runs/<run_id>.json                     (0..n)      cloud findings
```

`manifest.json` fields:

| field | meaning |
|---|---|
| `kind`, `schema` | identity (section 1) |
| `product_version` | the release that wrote the bundle, e.g. `intact-20260818` |
| `exported_at` | UTC ISO-8601 |
| `case_id`, `case_name` | the case as it was named on the source appliance |
| `member_run_ids`, `baseline_run_ids` | source ids, for reference only |
| `has_graph` | whether `graph.json` is present |
| `files[]` | `{path, sha256, bytes, role?}` — the inventory, see section 4 |
| `warnings[]` | what the export could not include, in operator language |

Only these guarantees are load-bearing: `kind`, `schema`, `files[]` and
`case.json`. Everything else is informative; treat its absence as unknown.

A bundle carries **one case and nothing else**. No credentials, no appliance
settings, no users, no other cases, and not the source case's activity log — an
audit trail of who did what on the customer's appliance belongs to the customer.
The imported case starts a fresh log whose first entry records the import.

## 4. `files[]` is the whitelist

The importer iterates `files[]`, not the ZIP's entry list, and matches every
`path` against a fixed pattern before touching it. A member absent from the
manifest is never read; a path that does not match the layout above is refused
outright. This — not the entry names — is the traversal defence, and it must stay
that way: entry names in a ZIP are attacker-controlled.

Checksums are verified for every listed file **before the first write**. A
bundle crosses an air gap on removable media, so a truncated copy is an ordinary
failure, and it has to be caught while the destination is still untouched.

## 5. Run ids are always remapped

Run ids are `<type>_<epoch_ms>`. Two appliances collecting at the same moment
mint the same id, so a bundle's ids may already exist on the destination and
mean something completely different.

Import therefore mints fresh ids for the case and every run, then rewrites every
reference to the old ones across `case.json`, `graph.json` and the run rows. The
rewrite is a bounded token replacement on the serialized JSON: ids are threaded
through evidence refs, `run_ids` lists, disposition targets, timeline finding
ids and the memory mapper's asset anchor, and a structured walk would miss one.

The predecessor implementation preserved source ids and saved rows with
`INSERT OR REPLACE`. On a collision it silently overwrote the destination's run
and re-tagged it into the imported case — stealing a run out of somebody else's
investigation with no error anywhere. Do not reintroduce that.

An import always creates a **new** case; it never merges into an existing one.

## 6. Payloads are the source of truth — and the forward-compat engine

This is the reason the format is a ZIP and not a JSON document.

`payloads/<run_id>/raw_results.json` (~547 MB for one collection),
`memory_payload.json` and `aws_runs/<run_id>.json` are the collected evidence.
On the destination there is no Velociraptor holding the original flow and no
VolWeb holding the YARA hits, so if these do not travel the imported case can be
read but never recomputed — frozen the day it was exported.

Because they do travel, **a future release does not have to understand an old
bundle in detail — it only has to be able to re-fuse it.** `graph.json` and the
report are convenience: they make the case open instantly, and a new release is
free to discard and rebuild them with its own engine.

Two consequences for future work:

* The snapshot-fallback readers in `store.py` (`_agentic_collected_data`,
  `_memory_contribution`, the `_velo_hunt_contribution` fallback, the cloud
  reader) are **load-bearing for this contract**. They are what let an imported
  run fuse with no live source behind it. They must not be removed or reduced to
  live-fetch-only.
* Payload files are written to the same paths a local run uses, so an imported
  run is indistinguishable from a native one to everything downstream. Keep it
  that way; special-casing "imported" runs anywhere in the fusion path would
  create a second code path that only breaks on the appliance nobody tests on.

## 7. What a failed import must leave behind

Nothing. Every row, payload directory, cloud file and graph sidecar an import
creates is recorded and removed if any step fails, and the case row's details are
written last — so a crash mid-import leaves an empty case an operator can delete,
never a case that looks complete and is quietly missing evidence.
