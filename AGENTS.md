# Notes for AI agents working on this repo

If you are an LLM (Claude Code / Cursor / Copilot / etc.) being asked to
clean up, refactor, or "secure" this repository, **read this before
deleting any file**. The author of this file (a previous LLM) made the
mistake described below; future-you can avoid repeating it.

## Files that MUST stay tracked, even though they look like secrets

The repository tracks a small number of files whose names or contents
look like things an over-zealous secrets-scrubber would remove. They
are intentional install-time files, not leaks. **Do not delete
them.** Do not move them out of the working tree, do not add them to
`.gitignore`, do not include them in any `git filter-repo --invert-paths`
list. Removing them breaks fresh installs.

### The list

| File | What it holds | Why it has to stay |
|---|---|---|
| `modules/backend/.env` | `ELASTICSEARCH_HOST=intact_elasticsearch`, `TIMESKETCH_PASS=` (empty), version pins, container-internal hostnames | Backend container's `docker-compose.yaml` does `env_file: - .env`. Missing file → `docker compose up` fails on a fresh clone. |
| `modules/elk/.env` | `ELASTIC_PASSWORD=` (empty), version pins | ELK stack's compose references it. Same pattern. |
| `modules/iris/.env` | service names + ports + `IRIS_VERSION` | IRIS compose env-file. |
| `modules/portainer/.env` | version pins only | Portainer compose env-file. |
| `modules/timesketch/.env` | `TIMESKETCH_PASSWORD=` (empty), version | TimeSketch compose env-file. |
| `modules/velociraptor/.env` | `VELOX_PASSWORD=` (empty), hostnames | Velociraptor compose env-file. `lib/config.sh:update_env_files` (run by `install.sh`) rewrites this in place at install time. |
| `modules/timesketch/config/timesketch.conf.template` | placeholder for `__TIMESKETCH_GOOGLE_AI_STUDIO_KEY__` | Rendered into `timesketch.conf` (gitignored) by `lib/common.sh:render_config_from_template`. |
| `modules/timesketch/config/timesketch_legacy.conf.template` | same | Same. |

### Why these files hold no passwords (and still must not be deleted)

The repo ships every password EMPTY: the module `password:` lines in
`config.yaml` and every `*PASSWORD*` value in the tracked
`modules/*/.env` files. The installer asks the operator for each one
(or generates it when there is no terminal), stores it per box in
`modules/<module>/secrets/` (0700 dir, 0600 files, gitignored, never
tracked) and blanks `config.yaml` again. `docs/SECRETS.md` has the
table of where each one lives; `sudo scripts/show-credentials.sh`
prints them.

So the lesson below still holds, for a different reason: the tracked
`.env` FILES must stay, because compose needs them — only their
password values are empty. If you find a real password in one of
them, blank the VALUE (the pre-commit hook does that to the staged
copy anyway); never delete or ignore the file. The old shipped values
(`123123`, `Ch4nge-Me!Intact2026`, `1234qwer!@#$`) are public, are
refused by the installer, and rotated by the upgrade wherever only
humans use them — do not reintroduce them as "defaults".

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
classified `modules/backend/.env` (which then contained
`TIMESKETCH_PASS=123123`, the old shipped placeholder) as a leak and
added it to the path-purge list. Result: the file was scrubbed from every commit on every branch
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
