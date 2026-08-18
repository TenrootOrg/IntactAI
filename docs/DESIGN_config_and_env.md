# Design: configuration that stays correct across releases

> **Status: design only.** Nothing here is implemented.
>
> **Goal:** a scheme where *any* future change to `config.yaml` or a module
> `.env` — a new key, a renamed key, a new default, a new module — reaches every
> existing box automatically, without anyone remembering to write migration code.

---

## 1. The problem: drift is structural, not accidental

Every configuration writer in the appliance treats **the box's existing file as
the substrate** and patches it in place:

| File | Mechanism | Consequence |
|---|---|---|
| `config.yaml` | 9 writers, all surgical line edits (`_pin_module_version`, `_intact_merge_versions`, `_intact_config_migrations`, `_intact_stamp`, `change_ip.sh`, `ensure_dashboard_login_is_reachable`, `write_first_login`, …) | only keys a writer explicitly names can ever appear |
| `modules/*/.env` | `update_env_files` (`lib/config.sh:383-578`) sets ~30 hardcoded keys via `update_env_var`, add-only on upgrade | a key no writer names never appears |

So a box's config keeps **the shape it had at install time**, forever. What a
release changes only reaches *fresh installs*.

### This has already caused real incidents

- **`versions.backend_tusd`** — introduced in 0726. Nothing on the upgrade path
  adds it, and `_intact_validate_config_pins` hard-fails without it, so **every
  0615 → 0813 upgrade died** on a key the box had no way to acquire.
- **`cloudtrail` → `aws_sigma`** — the same class, one release earlier. The code
  comment records that it "bit a customer on 0811 -> 0813, and it took intact's
  rollback down with it."
- **`ELASTICSEARCH_USER` / `ELASTICSEARCH_PASSWORD`** — a 0726 box upgraded to
  current had neither in `modules/backend/.env`; compose logged *"The
  `ELASTICSEARCH_USER` variable is not set."* `_intact_add_missing_env_keys`
  exists solely to paper over this.

Three incidents, one root cause. Each was fixed by adding another special case,
which is why the fourth is already latent (below).

### What is broken right now

`_intact_add_missing_env_keys` covers exactly the ~30 keys `update_env_files`
hardcodes, and only for **enabled** modules. A new **constant** key — the kind
that lives only in the tracked `.env`, such as anything in the `IRIS_*` block or
`ELK_CLUSTER_NAME` — is not covered at all. It reaches fresh installs and
**never** reaches an upgraded box. Nothing reports this.

---

## 2. The invariant

Everything below follows from one rule:

> **No configuration file is both release-owned and box-owned.**
> Every file is exactly one of three kinds, and ownership is a property of the
> **file**, never of individual keys inside it.

| Kind | Tracked? | Written by | Rule |
|---|---|---|---|
| **Template** | yes | humans, in git | release-owned. Never contains box state. |
| **Generated** | no (gitignored) | install/upgrade | fully derivable from *(template + config.yaml)*. Safe to delete and recreate at any moment. Never hand-edited. |
| **Box secret** | no | generated once | box-owned. Created once, never regenerated, never shipped, never overwritten. |

The consistency guarantee comes from the middle row: **a file that is always
regenerated cannot drift.** New keys, renamed keys, reordered keys, new comments
and new defaults all arrive for free, because the file is rebuilt from the
release's template every time rather than patched.

This is not a new invention for this codebase — **both halves already exist**,
applied to one module each:

- **Template → generated**: `modules/volweb/.env.template` is tracked; the
  rendered `modules/volweb/.env` is gitignored (`.gitignore:137-138`).
- **Secrets split out**: `modules/elk/secrets/kibana-keys.env`,
  `modules/timesketch/secrets/postgres.env` and
  `modules/portainer/secrets/agent.env` are already read via compose
  `env_file:`, for exactly this reason — *"NOT from `.env` — `.env` is tracked in
  git and a credential written there gets staged"*
  (`modules/elk/docker-compose.yaml:115-117`).

The design is to **finish these two conventions**, not to introduce a third.

---

## 3. Current state vs target

Six modules still keep credentials inside a tracked `.env`:

| File | Credential keys today | Target |
|---|---|---|
| `modules/backend/.env` | `ELASTICSEARCH_PASSWORD` | derived → generated `.env` |
| `modules/elk/.env` | `ELASTIC_PASSWORD`, `KIBANA_PASSWORD` | derived → generated `.env` |
| `modules/timesketch/.env` | `TIMESKETCH_PASSWORD` | derived → generated `.env` |
| `modules/velociraptor/.env` | `VELOX_PASSWORD`, `ELASTIC_PASSWORD` | derived → generated `.env` |
| `modules/volweb/.env` | `VOLWEB_POSTGRES_PASSWORD`, `VOLWEB_DJANGO_SECRET` | **generated-once → `secrets/`** |
| `modules/iris/.env` | `KEY_FILENAME` (a path, not a secret) | template |

The distinction that matters:

- **Derived secrets** (`ELASTIC_PASSWORD` ← `config.yaml modules.elk.password`,
  `TIMESKETCH_PASSWORD` ← `modules.timesketch.password`, …) are *regenerable*.
  They need no preservation — only a generated, untracked home.
- **Generated-once secrets** (`VOLWEB_DJANGO_SECRET`, `VOLWEB_POSTGRES_PASSWORD`,
  the IRIS `secrets/` set, `kibana-keys.env`, `postgres.env`) can never be
  recomputed. These are the only values that must survive, and they belong in
  `secrets/`.

Note `ELASTIC_PASSWORD` is **derived**, not generated-once — a distinction easy
to get backwards, and getting it backwards means either a stale credential or a
lost one.

---

## 4. Module `.env`: generalize volweb

**Target layout, every module:**

```
modules/<m>/.env.template     TRACKED    release-owned; placeholders + ${refs}
modules/<m>/.env              GENERATED  rendered from template + config.yaml
modules/<m>/secrets/*.env     BOX        generated once; read via compose env_file:
```

**Rendering** runs on every install *and* every upgrade: read the template, fill
each `${VAR}` from `config.yaml`, write `.env`. Because the output is a pure
function of *(template, config.yaml)*, it can simply be **overwritten** — there
is nothing in it worth preserving. That single property removes
`update_env_files`' 30 hardcoded keys, `UPDATE_ENV_ADD_ONLY`, and
`_intact_add_missing_env_keys` entirely.

**Secrets** are never rendered. `render_volweb_env_template`
(`lib/modules/volweb.sh:8-27`) is the reference for create-once-then-preserve
and keeps its semantics unchanged.

---

## 5. `config.yaml`: the one file that cannot be split

`config.yaml` is inherently mixed — it is the operator's file *and* it carries
release-owned pins — and it cannot become two files, because the backend
bind-mounts it as one. So it is the single exception where ownership is
**positional**, decided by one rule rather than a list:

> `versions:` and `schema_version` are **release-owned**.
> **Everything else is box-owned.**

This holds for the entire current file, verified against a live box:

| Release-owned | Box-owned |
|---|---|
| `schema_version` | `domain`, `first_login`, `project_name` |
| `versions.*` — all 22 keys, primary and sidecar | `options.*` (incl. `github_token`) |
| | `modules.<m>.enabled` |
| | `modules.<m>.id` / `.password`, `velociraptor.api_*` |

**Every secret lives outside `versions:`**, so "box wins outside `versions:`"
preserves all of them *by construction* — not by maintaining a list of keys to
copy. That is what makes the merge safe enough to attempt, and what keeps it
correct when a future release adds `modules.<newmod>.password`.

### The merge

```
1. migrate   run the schema-migration registry on the box's file
             (renames only — cloudtrail -> aws_sigma and its successors)
2. base      start from the RELEASE's config.yaml template:
             new keys, new sections, new comments, new defaults, canonical order
3. overlay   for every key NOT under versions:/schema_version,
             if the box has a value, the box's value wins
4. pins      versions:* comes from the release manifest
5. write     TRUNCATE IN PLACE (see §7)
```

Migrations shrink to their proper job — **renames and restructures only**. They
stop being the place where missing keys get filled in, which is what
`_intact_seed_missing_pins` currently does as a workaround.

---

## 6. The consistency guarantee, by example

The test of this design is what happens to a future change **with no engine code
written for it**:

| A future release… | Today | Under this design |
|---|---|---|
| adds `versions.foo_bar` | ✅ arrives (manifest) | ✅ arrives |
| adds `options.new_flag` | ❌ never | ✅ from the template |
| adds `modules.newmod` block | ❌ never | ✅ from the template |
| adds a constant `.env` key | ❌ **never** | ✅ `.env` is re-rendered |
| changes a `.env` default | ❌ never | ✅ re-rendered |
| adds a comment / reorders keys | ❌ never | ✅ from the template |
| renames a key | needs a migration | needs a migration *(unchanged — a rename genuinely needs intent)* |
| adds a new generated secret | needs code | needs code *(unchanged — creating a secret is a deliberate act)* |

Two rows still need human intent, and that is correct: a rename must state what
maps to what, and a new secret must state how it is generated. **Everything else
becomes automatic**, which is the requirement.

---

## 7. Constraints that any implementation must respect

1. **Inode preservation for `config.yaml` (hard blocker).** It is bind-mounted
   into `intact_backend` **by inode**
   (`modules/backend/docker-compose.yaml: ../../config.yaml:/app/config.yaml`).
   Writing a new file and `mv`-ing it leaves the container reading the old inode
   — the edit looks applied on disk and has no effect. The merge **must**
   truncate in place. `_pin_module_version` (`lib/config.sh:67-170`) already
   implements this correctly (fsync a temp copy for durability, then truncate the
   real file and write into it) and must be the primitive.
2. **No YAML round-trip.** `yaml.safe_load` + `dump` strips every comment and
   reorders keys. All editing is line-scan. (The *template* may be parsed to
   discover structure; the operator's file may not be rewritten from a parse.)
3. **A release currently ships no `config.yaml`.** The packager excludes it
   deliberately — the build machine's copy may hold real credentials
   (`scripts/ci/packager/package.py:1533-1545`). **This is the one prerequisite
   change**: the release must start shipping a *sanitized* template.
   `scripts/git-hooks/sanitize_config.py` already computes exactly that
   projection (`github_token` → `''`, module passwords → `123123`, `first_login`
   → `true`) and is unit-tested — reuse it in the packager rather than writing a
   second sanitizer. It currently does **not** sanitize `domain:`, which is why a
   real box IP is committed on `main` today; that must be fixed as part of this.
4. **`versions.backend` must never be momentarily absent.** An older release's
   writeback regex spins at 100% CPU without it, so the key must be present
   throughout the whole window, not merely at the end.
5. **`.env` files are never shipped and never mirrored** — the packager excludes
   `.env*` and `_intact_mirror` excludes them explicitly. Templates are new files
   and must be added to what ships.

---

## 8. Safety properties

The failure mode **inverts** under this design, and that must be designed for:

- Today, a mistake means a **missing key** — annoying, recoverable.
- Under template-first, a mistake means a **silently dropped secret** — and
  losing `modules.iris.password` locks the appliance out of its own case data.
  This is the same shape as the Velociraptor CA incident: silent, and discovered
  long after the fact.

Therefore, before any write:

```
ASSERT: every key present in the OLD config.yaml and not under
        versions:/schema_version is present in the NEW content with an
        identical value.
        Otherwise: abort, write nothing, report the exact key.
```

Plus:

- **`--dry-run` diff with values redacted** — keys and `added / kept / changed`
  only, never values. Turns "trust the merge" into "prove the merge."
- **Backups**: keep the existing `.pre-upgrade-backup` / `.pre-migration-backup`
  convention.
- **Idempotence test**: running the merge twice must produce a byte-identical
  file. Any difference is a bug in the merge.
- **Secret-count test**: the number of secret-classed keys must never decrease.

---

## 9. What this removes

Each of these exists only to compensate for drift, and is deleted by the design:

- `_intact_seed_missing_pins` — the `backend_tusd` fix
- `_intact_add_missing_env_keys` + `UPDATE_ENV_ADD_ONLY` — the missing-`.env`-key fix
- `update_env_files`' ~30 hardcoded keys — replaced by rendering a template
- `_intact_validate_config_pins`' duplicated sidecar table — pins arrive from the
  template, so the validator becomes a cheap assertion instead of a gate that can
  fail an upgrade on a key nothing writes

Net: **less** engine code, and the remaining code stops being a list that must be
kept in sync by memory.

---

## 10. Rollout

Ordered so that each phase is independently shippable and reversible:

1. **Ship the sanitized `config.yaml` template in the release.** No behaviour
   change; nothing reads it yet. Fix `sanitize_config.py` to cover `domain:`.
2. **Close the `.env` constant-key gap** for real — this is broken today. Can
   land before templates by extending rendering to one module (elk or backend) as
   a pilot.
3. **Convert modules to `.env.template` one at a time**, volweb's pattern, with
   the generated `.env` gitignored. Per-module, so a regression is contained.
4. **Move remaining generated-once secrets into `secrets/`** — only volweb's two
   values, since the rest are derived.
5. **Enable the `config.yaml` merge** behind a flag, with the assert and dry-run
   from §8, defaulting off. Compare merged vs current output on real boxes.
6. **Make the merge the default**, delete the compensating code from §9.

Steps 1–2 are worth doing regardless of whether 3–6 are ever approved.

## 11. Open questions

- **`options.download_tools`** — operator preference or release default? It is
  currently only ever set by hand, so the overlay rule treats it as box-owned.
  That is probably right, but it should be a decision, not an accident.
- **Removed keys.** If a release *deletes* a key, the overlay preserves the box's
  copy forever. Should removal be explicit (a migration) or should the template's
  absence win? Recommendation: **explicit migration** — silently dropping a key
  the operator set is the same class of harm this design exists to prevent.
- **Comments on box-owned keys.** The template's comments arrive, but a comment
  the *operator* added next to their own value has no home in a regenerated file.
  Accepted loss, or preserved on a best-effort basis?
