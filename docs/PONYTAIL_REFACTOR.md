# The ponytail safe-shrink campaign

A whole-repo pass to remove dead and duplicated code without changing
behaviour, driven by the ponytail rule-set (delete > reuse what exists >
stdlib > native > installed dep > one line > minimal code).

Branch `ponytail`, cut from `main` at `42012cd4`.

## What the ponytail plugin is, and is not

It is a rule-set injected into the assistant's context by a SessionStart hook
(v4.9.0, `~/.claude/plugins/marketplaces/ponytail`). It ships six markdown
skills, four small Node hook scripts and an MCP server that serves the same
text. **There is no code-transformation engine.** Every edit in this campaign
is a hand edit reviewed against the existing test suite. The plugin's headline
figure (~54% less code) is measured on newly written features, not on shrinking
an existing repository.

## Baseline

Measured 2026-09-08 at `42012cd4`. Lines are tracked files only, extensions
`.py .sh .js .html .css`, comments and blanks included.

| area | lines |
|---|---|
| modules/backend | 63,491 |
| modules/nginx (incl. vendored alpine/flatpickr/tus) | 16,053 |
| tests | 21,125 |
| lib | 17,089 |
| scripts | 12,594 |
| qa | 11,821 |
| install.sh | 398 |
| all Python (287 files) | 99,247 |
| all shell (126 files) | 33,030 |
| **SLOC, py+sh, non-blank non-comment** | **89,931** |

Comments and docstrings are 25-36% of the backend and are this repo's
institutional memory. They are not cut, so SLOC is the metric that decides
whether the campaign actually shrank anything.

Test wall time, this box, median of 3:

| suite | local median | CI (run 34210576845) |
|---|---|---|
| `tests/run_tests.sh` (90 suites) | 95.5 s | 81 s |
| `pytest tests/` (896 passed, 2 skipped) | 20.8 s | 18 s |

Local samples: shell 95.51 / 94.14 / 96.24, pytest 20.84 / 20.76 / 28.00 (the
third contended with other work on the box).

Where the shell time goes, from the CI log:

| suite | s |
|---|---|
| test_prepare_package.sh | 20.3 |
| test_core_deps.sh | 16.8 |
| test_autofuse.py | 9.7 |
| test_upgrade_core.sh | 6.3 |
| test_upgrade_health.sh | 5.5 |
| the other 85 suites | ~21 |

## Reproducing the measurement

```
for d in lib scripts modules modules/backend modules/nginx qa tests install.sh; do
  printf "%-16s %7d\n" $d $(git ls-files "$d" | grep -E '\.(py|sh|js|html|css)$' | xargs cat | wc -l); done

git ls-files | grep -E '\.(py|sh)$' | grep -v scratch_eval | xargs cat | grep -vE '^\s*(#|$)' | wc -l

for i in 1 2 3; do /usr/bin/time -f %e bash tests/run_tests.sh >/dev/null; done
for i in 1 2 3; do /usr/bin/time -f %e python3 -m pytest tests/ -q >/dev/null; done
```

CI comparison uses the `ci-next` steps "The shell suite" and "The Python
suite", PR run against the last `main` run, same runner class.

## Product speed

There is no product benchmark in this repo. The only runtime signal is the qa
harness's per-phase seconds in an e2e run. Any speed claim here is therefore
about the test suite, or about a phase duration in a named e2e run, never about
the appliance in general.

## The safety net

Coverage before this campaign came in three kinds, and only the first is a net:

- **A, behaviour**: the module is imported and its output asserted.
- **B, carve**: one function is cut out of the file by AST and executed alone.
- **C, source text**: a regex or AST shape is asserted against the file. A
  rename fails it; a logic bug passes it.

Roughly 35,000 lines had no coverage of any kind, including
`services/{aws,azure,memory,scheduler,llm_catalogs}`, 17 route files,
`lib/docker.sh`, and `install.sh`.

`tests/test_backend_import_smoke.py` closes the part of that gap the mechanical
edits can open. It imports all 148 modules under `modules/backend` for real,
with third-party packages stubbed, and so executes every module-scope
statement: decorator arguments, default arguments, re-exports, class bases.
That is exactly what a dropped import or a deleted "unused" function breaks.

It was verified by breaking something on purpose: commenting out the `flask`
import in `routes/aws_routes.py` turns it red with `NameError: name 'Blueprint'
is not defined`, and restoring the line turns it green.

Two supporting changes were needed in `tests/_optional_deps.py`:

- stubs are marked as packages (`__path__ = []`), otherwise
  `from apscheduler.schedulers.background import BackgroundScheduler` fails at
  the parent lookup before `sys.meta_path` is ever consulted;
- a finder appended to `sys.meta_path` resolves any submodule of a stubbed
  root. Appended, never prepended, so a genuinely installed package always wins.

`install_deps.py` is the one documented exclusion: it is a Dockerfile build
script that reads `sys.argv` at module scope, so importing it under pytest
makes it try to open pytest's own flag as a config file.

## Rules this campaign follows

| tier | what may change | proved by |
|---|---|---|
| A, behaviour-tested | dedupe, inline single-use helpers, simplify branches, delete dead paths | the covering suite, plus both full suites |
| B/C, tripwire only | mechanical edits; in-file dedupe only if the carved function keeps its exact name and signature | same, plus the tripwire itself |
| N, no coverage | mechanical only: unused imports, unused locals with a side-effect-free right-hand side, redefinitions, provably unreferenced functions | import smoke + the two AST lints |

Never, in any tier: rename a module-level name (source-text tests pin them from
other files), change a public signature, change a log or print string (the qa
probes and shell tests assert on them), touch the authentication routes or the
workspace-visibility guards, reorder a try/except, or collapse the repeated
`jsonify({'error': ...}), 500` tails into a Flask error handler.

When a source-text test fires, the default is to revert: most of them pin a
past bug fix, so failing one means the contract broke. Only if the assertion is
provably about spelling does it get updated, in the same commit.

## Considered and rejected

| candidate | why not |
|---|---|
| collapse the 87 identical 500-error tails into `@bp.errorhandler` | would also swallow `HTTPException` (404, abort) and drop the traceback logging, in code with no coverage |
| merge the AWS and Azure pipelines | per-function similarity 0.07-0.23. They are parallel, not duplicated. Merging is a rewrite |
| the four `_run_visible_in_active_workspace` guards | security guards with genuinely different inputs |
| `setup_velociraptor_connection` x3 | similarity 0.64-0.80, below the bar for a blind merge |
| log helpers in `scripts/clean.sh` and `generate_clients.sh` | standalone scripts; sourcing `lib/common.sh` would drag installer state in |
| trimming comments and docstrings | 25-36% of the backend, deliberately kept |
| `scripts/ci/packager/package.py` | one 1,866-line function, proved only by a real release build |
| `install.sh`, `lib/{package,health,permissions}.sh` | proved only by a real install; no stub-based test exists |
| the four backwards-compatibility re-export wrappers (109 of ruff's 240 findings) | their "unused" imports are the entire point of the file |

## Out of scope

`modules/nginx/html` (Alpine binds JS by string, three hand-versioned cache
layers, only two JS functions have executed tests), vendored JavaScript,
`scratch_eval/`, `.github/workflows` (it is the yardstick), `config.yaml` and
the `.env` files, and the live appliance.

## Results

Line delta against `main`, measured with `git diff main --numstat`:

| area | added | removed | net |
|---|---|---|---|
| modules/backend | 39 | 316 | -277 |
| qa | 0 | 64 | -64 |
| scripts | 22 | 7 | +15 |
| **product total** | **61** | **387** | **-326** |
| tests (the safety net) | 161 | 1 | +160 |
| docs (this file) | 156 | 0 | +156 |
| **repo total** | | | **-10** |

Test wall time, this box:

| suite | before | after |
|---|---|---|
| test_prepare_package.sh | 20.52 s | 0.62 s |
| test_core_deps.sh | 22.18 s | 6.51 s |
| shell suite, all 85 | 95.5 s | ~60 s |

### What was removed

- 106 unused imports across 48 files, excluding the four backwards-compatibility
  re-export wrappers whose "unused" imports are the entire point of the file.
- Four unused exception bindings and one duplicate `import os`.
- Ten unreferenced functions in the backend (221 lines) and four in the qa
  harness (57 lines). Each was checked three ways before deletion: no reference
  anywhere in the tree including quoted strings, no decorator that could route
  to it, and absent from every `__all__`.

`services/data_anonymizer.py` lost `unmask_text`, `get_mapping_summary` and
`get_masking_log_lines`. Flagging that deliberately: `unmask_text` was the only
way to reverse a masking, so this is a product decision, not just cleanup. It
had no callers and is recoverable from git history.

### Three stalls fixed

All three were found by tracing executed commands with a timestamped `PS4`,
after the planned cause turned out to be wrong. The plan blamed a `sleep` in
the GPG retry loop of `lib/deps.sh`; that suite stubs `install_docker`, so the
loop never runs.

| where | cause | measured |
|---|---|---|
| `tests/helpers.sh` `path_without()` | forked `basename` per binary, ~3,500 forks per call | 22.18 s to 6.51 s |
| `scripts/prepare_package.sh` watcher | background subshell held the stdout pipe, so any `$(...)` caller waited for its orphaned `sleep` | 20.19 s to 0.37 s |
| `scripts/prepare_package.sh` `_dl_watch` | slept a full tick before its first liveness check, once per part | 15.00 s to 1.00 s |

The second is a defect in shipped code. The README documents
`wrapper=$(prepare_package.sh ...)`, and every such caller paid ~20 s after the
work had finished. Redirecting the `printf` changes nothing, which was measured
before it was believed: holding the descriptor is what blocks, not writing to
it.

### Left alone, with reasons

- 113 unused imports remain, essentially all in `__init__.py` re-export
  facades where the import IS the public interface.
- 13 unused locals remain. Each has a function call on the right-hand side, so
  removing the assignment could drop a side effect. Two of them,
  `cancel_event = register_cancel_event(run_id)` in `azure_routes.py` and
  `maintenance_routes.py`, are safe but not worth a line: the call registers
  into a run-keyed registry and cancellation is read back with
  `is_cancelled(run_id)`. Sibling call sites already discard the return.
- The malformed shellcheck directive at `tests/helpers.sh:85` predates this
  branch and sits outside the file list CI gates.
- The five model-catalogue modules were the largest planned dedupe, ~400 lines.
  Reading them killed it: only two of the five share a shape. Gemini carries
  extra token-preservation logic, OpenRouter has neither key nor enrichment,
  and Codex is not HTTP at all. Folding the remainder saves ~50 lines and needs
  ~80 lines of new test to be safe, so the line count goes up. Rejected on its
  own metric.
