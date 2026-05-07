# Secrets handling

Where every kind of secret in this project lives, and how to add a
new one safely.

## TL;DR for operators on a fresh install

```bash
# Optional — only set if you have a key. Otherwise NL2Q + LLM
# providers in TimeSketch stay disabled and the rest still works.
export TIMESKETCH_GOOGLE_AI_STUDIO_KEY="AIza..."

sudo bash scripts/first-init.sh
# (or `sudo ./install.sh` if you're using the full installer)
```

After install, configure the rest through the **Settings** page in the
dashboard:

| Secret | Set via |
|---|---|
| Anthropic / OpenAI / OpenRouter / Google AI Studio LLM keys | Settings → Agentic |
| Azure tenant_id / client_id / client_secret | Settings → Cloud → Azure |
| AWS access key / secret | Settings → Cloud → AWS |
| TimeSketch user password | `config.yaml` (operator-controlled) |
| IRIS admin password | `config.yaml` |

## Where each kind of secret is stored at runtime

| Secret type | Storage | Notes |
|---|---|---|
| **LLM API keys** (Anthropic, OpenAI, OpenRouter, Google AI Studio used by the agentic pipeline) | `data/frontend_data.db` (SQLite, gitignored) under the `frontend_config` table key `agentic` | Saved by the Settings UI via `POST /api/config`. Read at run time by `services/storage/config_store.py:load_frontend_config`. **Never** read from `config.yaml` or any tracked file. |
| **Azure app-auth credentials** (tenant_id, client_id, client_secret) | `data/frontend_data.db` under `frontend_config` key `cloud.azure` | Saved via `POST /api/config/cloud`. Read at run time by `routes/config_routes.py:_load_cloud_config`. The `client_secret` is masked as `••••••••` on `GET /api/config/cloud`. |
| **Azure app-auth certificate** (private key + public PEM) | `data/azure_cert.pfx`, `data/azure_cert_public.pem` (both gitignored) | Generated at install. Path constants live in `services/azure/dfir_o365rc.py`. Operator uploads the public key to Azure portal. |
| **TimeSketch Google AI Studio key** (used by `timesketch.conf` for nl2q / summarize / synthesize) | Either: <br>(a) `${TIMESKETCH_GOOGLE_AI_STUDIO_KEY}` env var, baked in at install time by the template-render step, OR <br>(b) hand-edited into `modules/timesketch/config/timesketch.conf` after install (the rendered file is gitignored). | The `.template` file is tracked; the rendered `.conf` is not. |
| **IRIS / Postgres / TimeSketch user passwords** | `config.yaml` (operator-managed) → propagated by `scripts/first-init.sh` into per-module `.env` and secrets dirs (`modules/iris/secrets/`, `modules/portainer/secrets/`) — all gitignored. | The default values in `config.yaml` are placeholders meant to be overwritten before install. |

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
     `lib/modules.sh`) or the inline `render_module_configs` in
     `scripts/first-init.sh`.
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

`scripts/first-init.sh` auto-runs `pre-commit install` when run from
a developer clone (i.e. `.git` exists and `pre-commit` is on PATH).
Production / operator installs from a tarball skip this silently.

## CI

`.github/workflows/secret-scan.yml` runs gitleaks on every push and
pull request to `main` / `development`. It catches commits that
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
