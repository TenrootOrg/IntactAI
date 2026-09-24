# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

**Read [AGENTS.md](AGENTS.md) before deleting or "scrubbing" any file.** The `modules/*/.env` files and the `123123` passwords are tracked install-time defaults, not leaked secrets; purging them once broke every fresh install.

## What this is

Intact.AI is a DFIR appliance for Ubuntu 24.04. It wires together Velociraptor, Timesketch/Plaso, ELK, IRIS, VolWeb and Portainer as Docker Compose stacks, with a Flask backend and a static dashboard in front of them. The repo holds the platform source and its installer/upgrade engine. The installed appliance is a separate, non-git tree (on this box: `/home/tenroot/intact`), and this worktree is `main`.

## Commands

```bash
bash tests/run_tests.sh                    # whole suite: plain bash + stdlib python3, nothing to install
python3 tests/test_case_fuse_races.py -v   # one Python suite (each file runs standalone via unittest)
bash tests/test_upgrade_plan.sh            # one shell suite (each file is its own subprocess)
bash scripts/install-git-hooks.sh          # enables the pre-commit hooks (config sanitizer + secret guard)
bash scripts/scan-secrets.sh               # secrets audit before any force-push or release tag
```

- Run targeted suites for a change. Ask before running the full suite.
- `tests/*.js` are jsdom drivers for the real pages. Their `test_*_live_page.py` wrappers need a live appliance and skip everywhere else.
- `tests/_optional_deps.py` stubs `grpc` and similar imports so `services.*` imports without the container's dependencies. New Python tests that import backend services need it.
- `qa/run_qa.py` is the end-to-end harness (install → drive → assert → tear down). It takes `--only` and `--skip` phase lists. CI runs it through `.github/workflows/e2e.yml`, which is `workflow_dispatch`-only.
- CI `test.yml` runs `tests/run_tests.sh` on every push to `main`. Release assets are built by `build-release-assets.yml` (dispatch-only) using `scripts/ci/build_release_package.py`.

## Architecture

**Install.** `install.sh` sources `lib/*.sh` (`config.sh`, `docker.sh`, `package.sh`, …). `lib/modules/orchestrator.sh` then runs one `lib/modules/<module>.sh` per enabled module, and each of those drives `modules/<module>/docker-compose.yaml`. `config.yaml` is the single operator-facing config. `lib/config.sh:update_env_files` renders it into each module's `.env`. `--package <tar>` makes the whole install run offline.

**Backend (`modules/backend/`).** A Flask app (`app.py`) with one blueprint per area in `routes/` and the logic in `services/`. The large subsystems are `services/fusion/` (Case Analysis: correlation, identities, reports, chat; see its README and `CASE_BUNDLE_CONTRACT.md`), `services/agentic/`, `services/memory/`, `services/aws/`, `services/azure/` and `services/scheduler/`. Runtime state lives in SQLite at `data/intact.db`. Real secrets (LLM keys, Azure creds) go into the DB through the Settings page and never into tracked files. Default blueprints come from `config/default_blueprints.yaml` and are re-seeded on every restart, so edit the YAML, not the DB. `ARCHITECTURE.md` in that directory predates most of these subsystems.

**The code is baked into the image, not bind-mounted.** `intact-backend:<release>` contains the backend source. A Python edit does nothing until the image is rebuilt or `scripts/dev/push_backend.sh` copies it into the running container; that copy survives `docker restart` but not a recreate. When deploying a built image to the appliance, pin the tag in both `modules/backend/.env` (`BACKEND_VERSION`, which compose reads) and `config.yaml` (`versions.backend`, which the next install or upgrade uses to regenerate `.env`). Also pass `docker compose up --no-build`, or compose rebuilds the tag from the appliance's old source. On every start, `services/upgrade_launcher.py:ensure_host_engine()` rewrites the appliance's `lib/` and `scripts/` from the copy baked into the image, so rebuild the image before restarting after engine edits.

**Frontend (`modules/nginx/html/`).** Static HTML and JS served by nginx through a bind mount, so edits go live on refresh. Cache busting uses `?v=N` query strings maintained by hand, and they are nested. The chain is `index.html` → `js/bootstrap/partial-loader.js?v=` (one version for every partial) → `partials/*.html?v=` → for Case Analysis, an iframe `cases.html?...&v=`. Bump every version on the path from `index.html` down to the changed file, or the change stays invisible. Tailwind is built with `build-tailwind.sh`.

**Upgrade engine.** `scripts/upgrade.sh` drives the modules in `lib/upgrade/` (`plan.sh`, `core.sh`, and one module file per stack under `modules/`). An upgrade runs the target release's own code against the live tree. The backend moves by image swap in two phases: phase 1 runs on the old code, loads the new image and hands off to a helper container that recreates `intact_backend`, then phase 2 resumes inside the new container. Anything phase 1 touches is a backward-compatibility surface: package layout, container names, `BACKEND_VERSION` and `INTACT_HOST_PATH` in `.env`, and state kept outside the container. Read `docs/UPGRADE_CONTRACT.md` before changing any of it. Never add a `./services` bind mount back to the backend compose, because `backend_full_mode()` uses its absence to detect the release type. Upgrades must preserve evidence and data. The Velociraptor CA (`data/velociraptor/`) and the search-engine volumes are the known traps. Rolling ELK back to an older `ELASTIC_VERSION` leaves Elasticsearch unable to start.

**Per-box state.** `lib/state_registry.sh` moves secrets and certs under `data/state/` and leaves symlinks at the old paths. Everything under `data/` except `.gitkeep` placeholders is local state.

## Repo conventions

- `config.yaml` is tracked. The pre-commit hook (`scripts/git-hooks/sanitize-config-yaml.sh`) rewrites the staged blob back to defaults (token cleared, passwords `123123`) and leaves the working file untouched. It does not sanitize `domain:`. A release does not ship `config.yaml`. The backend mounts the file by inode, so writers must truncate in place (reuse `_pin_module_version` in `lib/config.sh`); never write a temp file and `mv` it.
- The installer writes live credentials into `modules/*/.env` at runtime. Never run `git add -A modules/`.
- Comments in this codebase explain *why* (the incident, the trap). Keep that style when editing nearby code.
- `.claude/notes/known-bugs.md` lists known, not-yet-fixed bugs.
