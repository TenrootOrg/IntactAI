# Changelog / Release Notes

Operator-facing notes for IntactAI platform releases. Newest first. Pull the
relevant section into the GitHub release body when tagging.

## Unreleased

### Timesketch `20260617` — OpenSearch must be upgraded first

Bumped `versions.timesketch` `20260611` → `20260617`
(ref: <https://github.com/google/timesketch/releases>).

**OpenSearch dependency.** Timesketch **20260611+** requires **OpenSearch
≥ 2.19.5** (native wildcard field mapping; the base image also moved to Ubuntu
26.04). **20260617** additionally notes that hosts already on **OpenSearch 3.x**
must be on **≥ 3.7.0**. Our pin stays at `versions.timesketch_opensearch:
2.19.5`, which satisfies `20260617` on the 2.x line — no OpenSearch tag change
is needed for this bump.

**Upgrade ordering — OpenSearch first, then Timesketch.** OpenSearch is brought
up and made healthy **before** the Timesketch `web` / `worker` containers, and
this is enforced automatically — `modules/timesketch/docker-compose.yaml`
declares:

```yaml
timesketch-web:
  depends_on:
    timesketch-opensearch:
      condition: service_healthy   # + a 5-minute OpenSearch start grace
```

So Timesketch never starts against an un-upgraded / not-yet-ready OpenSearch,
and **no manual step is required**. This holds identically on **all three
paths**, because each runs the same `docker compose up -d` against the
timesketch stack:

- **Online upgrade** (dashboard / `services/upgrade/timesketch.py:upgrade_timesketch`)
- **Offline / air-gap upgrade** (`upgrade_timesketch_offline`) — the new
  OpenSearch image is loaded from the package before compose up
- **Offline fresh install** (`install_timesketch_offline`) — if no existing
  stack is detected, OpenSearch is created + health-gated ahead of Timesketch
  the same way

**When bumping Timesketch in `config.yaml`,** bump `timesketch_opensearch` to the
matching minimum in the *same* change. A **2.x → 3.x** OpenSearch move is a
**MAJOR** upgrade (reindex / rolling upgrade) — plan it deliberately; do not
just swap the tag.
