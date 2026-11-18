# Secrets handling

Where every kind of secret in this project lives, and how to add a
new one safely.

> **AI agents:** Before deleting any file in this repo as part of a
> "scrub secrets" task, read [`AGENTS.md`](../AGENTS.md). Some files
> look secret-shaped but are install-time defaults that must stay
> tracked — removing them breaks fresh installs.

## Files that look like secrets but must stay tracked

These are install-time files (container-internal hostnames, version
pins, and password keys whose values ship EMPTY). Compose needs them.
Never include them in a history-rewrite path-purge list.

* `modules/backend/.env`
* `modules/elk/.env`
* `modules/iris/.env`
* `modules/portainer/.env`
* `modules/timesketch/.env`
* `modules/velociraptor/.env`
* `modules/timesketch/config/timesketch.conf.template`
* `modules/timesketch/config/timesketch_legacy.conf.template`

They hold no password values: the real ones are per box, in
`modules/<module>/secrets/` (see [Module passwords](#module-passwords)).
See [`AGENTS.md`](../AGENTS.md) for the full list and the postmortem of
the time one got removed by accident.

## TL;DR for operators on a fresh install

```bash
# Optional — only set if you have a key. Otherwise NL2Q + LLM
# providers in TimeSketch stay disabled and the rest still works.
export TIMESKETCH_GOOGLE_AI_STUDIO_KEY="AIza..."

sudo bash install.sh     # asks for each module password, or press Enter to generate
sudo bash scripts/show-credentials.sh   # prints them again later
```

After install, configure the rest through the **Settings** page in the
dashboard:

| Secret | Set via |
|---|---|
| Anthropic / OpenAI / OpenRouter / Google AI Studio LLM keys | Settings → Agentic |
| Azure tenant_id / client_id / client_secret | Settings → Cloud → Azure |
| AWS access key / secret | Settings → Cloud → AWS |
| Module passwords (Elasticsearch, Timesketch, Velociraptor, IRIS, VolWeb, Portainer) | the installer prompt, or `config.yaml` before install (blanked afterwards) — see [Module passwords](#module-passwords) |

## Where each kind of secret is stored at runtime

| Secret type | Storage | Notes |
|---|---|---|
| **LLM API keys** (Anthropic, OpenAI, OpenRouter, Google AI Studio used by the agentic pipeline) | `data/frontend_data.db` (SQLite, gitignored) under the `frontend_config` table key `agentic` | Saved by the Settings UI via `POST /api/config`. Read at run time by `services/storage/config_store.py:load_frontend_config`. **Never** read from `config.yaml` or any tracked file. |
| **Azure app-auth credentials** (tenant_id, client_id, client_secret) | `data/frontend_data.db` under `frontend_config` key `cloud.azure` | Saved via `POST /api/config/cloud`. Read at run time by `routes/config_routes.py:_load_cloud_config`. The `client_secret` is masked as `••••••••` on `GET /api/config/cloud`. |
| **Azure app-auth certificate** (private key + public PEM) | `data/azure_cert.pfx`, `data/azure_cert_public.pem` (both gitignored) | Generated at install. Path constants live in `services/azure/dfir_o365rc.py`. Operator uploads the public key to Azure portal. |
| **TimeSketch Google AI Studio key** (used by `timesketch.conf` for nl2q / summarize / synthesize) | Either: <br>(a) `${TIMESKETCH_GOOGLE_AI_STUDIO_KEY}` env var, baked in at install time by the template-render step, OR <br>(b) hand-edited into `modules/timesketch/config/timesketch.conf` after install (the rendered file is gitignored). | The `.template` file is tracked; the rendered `.conf` is not. |
| **Module passwords** (Elasticsearch, Timesketch, Velociraptor, IRIS, VolWeb, Portainer) | `modules/<module>/secrets/` only (0700 dir, 0600 files, gitignored) | See [Module passwords](#module-passwords). `config.yaml` and the tracked `.env` files ship them empty. |
| **Dashboard setup token** | `data/state/backend/setup_token` (0600) | Created by `install.sh` and by `sudo scripts/reset-login.sh`; `/api/auth/setup` requires it and deletes it on use. |

## Module passwords

The repo ships every module password **empty** — the `password:` lines
in `config.yaml` and every `*PASSWORD*` value in the tracked
`modules/*/.env`. A value that is in this public repo is no secret,
and the old shipped ones (`123123`, `Ch4nge-Me!Intact2026`,
`1234qwer!@#$`, `changeme`) are refused wherever a password is set.

**The rule** (one that every bundled tool accepts at first start): 12+
characters with an uppercase letter, a lowercase letter and a digit;
only `A-Z a-z 0-9 - _ .`, not starting with `- _ .`; not a known
default. The tools' own minimums are lower (Elasticsearch 6+; IRIS 12+
with upper/lower/digit; Portainer 12+, or its admin is never created;
Timesketch, Velociraptor and VolWeb none). Code: `lib/secrets.sh`.

**At install**, per module: a stored password is kept; otherwise a
value typed into `config.yaml` is checked against the rule; otherwise
the installer asks on the terminal (hidden, typed twice; Enter
generates one); with no terminal it generates one. A password is only
generated for a tool that has no data yet — a tool with existing data
keeps the password it already has, because it would refuse a new one.
`config.yaml` is then blanked again in place. At the end the human
credentials are shown once on the terminal; with no terminal nothing is
written anywhere else — view them with `sudo scripts/show-credentials.sh`.

**Where each one lives** (the only copy on the box):

| Module | File | Keys | Used by |
|---|---|---|---|
| elk | `modules/elk/secrets/creds.env` | `ELASTIC_PASSWORD` (user `elastic`), `KIBANA_PASSWORD` (`kibana_system`, random, never shown) | Elasticsearch, Kibana, Logstash, the elk setup container, the backend, Velociraptor (Elastic upload artifact) |
| timesketch | `modules/timesketch/secrets/creds.env` | `TIMESKETCH_PASSWORD` (the `id` user from `config.yaml`) | Timesketch admin creation, the backend |
| velociraptor | `modules/velociraptor/secrets/creds.env` | `VELOX_PASSWORD` (GUI user `id`), `VELOX_PASSWORD_2` (user `api`, random, never shown) | the Velociraptor entrypoint only |
| iris | `modules/iris/secrets/IRIS_ADM_PASSWORD` | — | IRIS first init, `enforce_iris_admin_password` |
| volweb | `modules/volweb/secrets/ADMIN_PASSWORD` | — | VolWeb seeding, the backend's VolWeb client |
| portainer | `modules/portainer/secrets/admin_password` | — | Portainer `--admin-password-file` (first start only) |

Compose loads the `creds.env` files with `env_file`, so nothing else
has to be kept in step with them. Never put one of these values in a
compose `${VAR}`: interpolation reads the project `.env`, not
`env_file`, and puts the value in `docker inspect`.

**Reading them back:** `sudo bash scripts/show-credentials.sh` prints
`module | user | password` from the stores (not `api`, not
`kibana_system`, which no human uses).

**Changing one later:** type the new value into `modules.<module>.password`
in `config.yaml` and run `sudo bash scripts/apply-passwords.sh`. For each
module with a value it sets the password inside the tool, updates the store,
restarts what reads it (backend, Logstash, Kibana, Velociraptor), checks the
logins, and puts everything back if any step fails. A line is blanked again
only after its module succeeded; the script prints `changed` or
`reverted: <reason>` per module, never a value (or `FAILED, not fully put
back: <reason>` when it could not confirm the old state -- check that tool,
then re-run). Hangups and Ctrl-C are ignored while it runs, and a run cut off
anyway (power loss) is finished by the next one. A Portainer whose password
is "unknown" (placeholder): set it in the Portainer UI, then put that value
in `config.yaml` and run the script -- it adopts it. Upgrades never apply
`config.yaml` passwords on their own.

**Intact owns these passwords.** The Velociraptor entrypoint re-applies the
stored GUI and `api` passwords only when the stored value changes (it keeps a
hash of the last one it applied). A password changed by hand in the
Velociraptor UI therefore survives restarts and no longer matches the store.
Change them with `apply-passwords.sh`, not in the tools' own UIs.

**The backend's way into Velociraptor.** Everything Intact does in
Velociraptor goes through the user `api` and its certificate,
`api.config.yaml`. `sudo bash scripts/velociraptor-api-check.sh` checks it:
the container is up, the certificate is for `api` and signed by the server's
current CA, `api` exists with `administrator` and `api`, its password is the
stored one, and the backend's own client gets through. Add `--fix` to repair
what it finds. It re-creates `api` with both roles and the stored password,
regenerates the certificate, or starts Velociraptor; the repairs restart
Velociraptor for about 20 s. Run it if anyone deleted `api` or changed its
roles in the Velociraptor UI: that stops every Velociraptor feature of Intact,
and a restart alone does not bring `api` back.

**Lab boxes:** `allow_weak_passwords: true` in `config.yaml` lets weak or
publicly known passwords (e.g. `123123`) through and stops upgrades from
rotating them. Never on a box anyone else can reach; committing resets it.

**Dashboard login:** a separate account, set in the browser. Setup
needs the one-time token from `data/state/backend/setup_token`
(printed at install). Forgot the password, locked out (ten wrong
attempts from one address), or want a new token:
`sudo bash scripts/reset-login.sh` (writes a new token, sets
`first_login: true` and prints the token). Setting `first_login: true`
by hand no longer re-opens setup on its own: setup needs the token. The
12+ rule applies when the password is set or changed, never at login.

**Upgrades** never change a password a machine logs in with
(Elasticsearch `elastic`, the Timesketch user, the VolWeb admin):

- *Migrate:* a password that an old box keeps in its live
  `modules/<module>/.env` or `config.yaml`, and that is missing from
  the store, is copied unchanged into the store and blanked where it
  was.
- *Rotate:* publicly known values that only humans use are replaced —
  the Velociraptor GUI user and `api`, the Portainer admin, the IRIS
  administrator, and Timesketch's `SECRET_KEY` when it equals the value
  once published in this repo.
- *Keep and warn:* a machine-used password still on a known default is
  kept, and Settings shows "default password in use" for that module.

This runs for every installed module, including one the upgrade does not move
and one the dashboard's `--only` leaves out — a module's version not changing
is no reason to keep a public password.

## Rules for adding a new secret

1. **Never hardcode** a secret in a tracked file. Even a "temporary"
   placeholder like `'api_key': 'AIza…'` ends up cached on GitHub
   forever once committed.

2. **Default storage is `data/frontend_data.db`.** Add a new key under
   the `frontend_config` table, surface it through Settings,
   `POST /api/config/<thing>`. The DB is gitignored.

3. **If the secret has to live in a tracked config file** (e.g. a
   third-party config the container reads at startup), template it:
   - Commit `config.template` with a `__PLACEHOLDER__` token.
   - Add `config` (the rendered output) to `.gitignore`.
   - Render at install time via
     `lib/common.sh:render_config_from_template` (used by
     `lib/modules.sh`).
   - The render reads the value from an environment variable; absent
     env var = empty substitution = the consuming service sees an
     empty / disabled config.

4. **Dev / maintenance scripts** (anything under `data/` or
   `scripts/` that an operator runs by hand) **never hardcode**
   tenant IDs, client IDs, or API keys. Pull from the source-run
   JSON, the runtime config DB, or an env var. Pattern from
   `data/replay_llm.py`:

   ```python
   tenant = (
       (src.get("azure_config") or {}).get("tenant_id")
       or os.environ.get("AZURE_TENANT_ID", "")
   )
   ```

5. **Run `bash scripts/scan-secrets.sh`** before any force-push or
   release tag. It runs gitleaks against the staged diff, working
   tree, and full history.

## Pre-commit hook

```bash
pip install pre-commit
pre-commit install
```

After that, every `git commit` runs gitleaks on the staged diff. A
hit blocks the commit. Don't bypass with `--no-verify`; if the
finding is a false positive, add an entry to `.gitleaks.toml`
under `[allowlist]` with a comment explaining why.

Run the two commands above once per developer clone. Also run
`bash scripts/install-git-hooks.sh`: its pre-commit hook rewrites the
STAGED copy of `config.yaml`, `qa/qa-config.yaml` and any
`modules/*/.env` back to shipping values (token and every password
empty) and leaves your working files untouched. Production /
operator installs from a tarball have no `.git`, so the hook simply
doesn't apply there.

## CI

`.github/workflows/secret-scan.yml` runs gitleaks on every push and
pull request to `main` / `development` / `dev`. It catches commits that
bypassed the local hook.

## Rotating leaked secrets

If a secret made it onto GitHub:

1. **Rotate immediately** in the issuing system (Google Cloud
   Console / Azure App Registration / OpenAI dashboard / etc.).
   Treat the old value as compromised regardless of whether you
   rewrite git history.
2. Replace the leaked value in the working tree with a placeholder
   or env-var lookup (see the template pattern above).
3. Optionally rewrite history — see the runbook below.
4. Notify any consumers of the old value to fetch the rotated
   credential.

## Runbook — rewriting history to scrub a leaked secret

```bash
# 1. Make a backup of the whole repo (including .git):
TS=$(date -u +%Y%m%dT%H%M%SZ)
tar --exclude=client_installers --exclude='data/azure_runs' \
    --exclude='data/tmp' \
    -czf "/home/tenroot/intact-backup-${TS}.tar.gz" intact

# 2. Install git-filter-repo if missing:
pip install --user git-filter-repo

# 3a. To replace string content (keep file, redact the string):
cat > /tmp/replace.txt <<'EOF'
literal:THE_LEAKED_STRING==>REDACTED-REPLACEMENT
EOF
git-filter-repo --replace-text /tmp/replace.txt --force

# 3b. OR to remove a file from history entirely:
echo "path/to/leaked-file.json" > /tmp/paths.txt
git-filter-repo --invert-paths --paths-from-file /tmp/paths.txt --force

# 4. filter-repo strips the `origin` remote as a safety check. Re-add:
git remote add origin git@github.com:TenrootOrg/IntactAI.git

# 5. Force-push every branch + tag:
git push origin --force --all
git push origin --force --tags

# 6. Verify with gitleaks against post-rewrite history:
bash scripts/scan-secrets.sh --history
```

After the rewrite, anyone with a clone needs to re-clone (or rebase
their local branches onto the rewritten history). On a single-developer
project this is a non-issue.
