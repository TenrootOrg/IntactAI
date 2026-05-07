# Notes for AI agents working on this repo

If you are an LLM (Claude Code / Cursor / Copilot / etc.) being asked to
clean up, refactor, or "secure" this repository, **read this before
deleting any file**. The author of this file (a previous LLM) made the
mistake described below; future-you can avoid repeating it.

## Files that MUST stay tracked, even though they look like secrets

The repository tracks a small number of files whose names or contents
look like things an over-zealous secrets-scrubber would remove. They
are intentional install-time defaults, not leaks. **Do not delete
them.** Do not move them out of the working tree, do not add them to
`.gitignore`, do not include them in any `git filter-repo --invert-paths`
list. Removing them breaks fresh installs.

### The list

| File | What it holds | Why it has to stay |
|---|---|---|
| `modules/backend/.env` | `ELASTICSEARCH_HOST=intact_elasticsearch`, `TIMESKETCH_PASS=123123`, version pins, container-internal hostnames | Backend container's `docker-compose.yaml` does `env_file: - .env`. Missing file → `docker compose up` fails on a fresh clone. |
| `modules/elk/.env` | `ELASTIC_PASSWORD=123123`, version pins | ELK stack's compose references it. Same pattern. |
| `modules/iris/.env` | service names + ports + `IRIS_VERSION` | IRIS compose env-file. |
| `modules/portainer/.env` | version pins only | Portainer compose env-file. |
| `modules/timesketch/.env` | `TIMESKETCH_PASSWORD=123123`, version | TimeSketch compose env-file. |
| `modules/velociraptor/.env` | `VELOX_PASSWORD=123123`, hostnames | Velociraptor compose env-file. `scripts/first-init.sh:sync_velociraptor_env` rewrites this in place at install time. |
| `modules/timesketch/config/timesketch.conf.template` | placeholder for `__TIMESKETCH_GOOGLE_AI_STUDIO_KEY__` | Rendered into `timesketch.conf` (gitignored) by `lib/common.sh:render_config_from_template`. |
| `modules/timesketch/config/timesketch_legacy.conf.template` | same | Same. |

### Why the `123123` value isn't a secret leak

`123123` is the canonical install-time placeholder password. It's
intentionally weak and visible — operators see it in `config.yaml`,
the install banner prints it, and the install wizard prompts the
operator to rotate it. Tracking it in the .env files is the same
posture as shipping a router with `admin/admin` defaults: it's a
starter, not a secret. Don't try to scrub it.

### What gets scrubbed instead

Real secrets — Anthropic / OpenAI / OpenRouter API keys, Azure tenant
credentials, Azure cert PFX, runtime data dumps — go into
`data/frontend_data.db` (gitignored) via the dashboard Settings page.
None of those ever land in tracked files. The pre-commit gitleaks
hook (`.gitleaks.toml` + `.pre-commit-config.yaml`) is the actual
defense for that class. See `docs/SECRETS.md` for the full pattern.

## How this lesson got learned

On 2026-05-07 a previous LLM (this one, Claude Opus 4.7) was asked to
scrub committed secrets from history. It correctly identified real
leaks (a tenant GUID in `data/replay_llm.py`, two Google AI Studio
keys in `timesketch.conf`, runtime data dumps under `data/azure_runs/`)
and used `git-filter-repo` to remove them. It also incorrectly
classified `modules/backend/.env` (which contained
`TIMESKETCH_PASS=123123`) as a leak and added it to the path-purge
list. Result: the file was scrubbed from every commit on every branch
and force-pushed, breaking fresh-install on `main` until the operator
noticed several hours later. The rest of the .env files survived only
because they happened not to contain the literal string the LLM had
flagged.

The fix is documented in commits `8545c82` (development) and
`32758a8` (main). The lesson is documented here.

## Related guidance

* `docs/SECRETS.md` — full policy on where each kind of secret lives,
  pre-commit hook setup, history-rewrite runbook.
* `.gitleaks.toml` — rules + allowlist for the pre-commit + CI scans.
* `scripts/scan-secrets.sh` — pre-push audit. Run before any
  force-push or release tag.
