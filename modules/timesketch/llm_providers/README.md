# Timesketch contrib LLM providers

IntactAI adds two LLM providers to Timesketch that upstream does not ship:

| Provider | Timesketch `NAME` | Talks to |
|---|---|---|
| `openrouter.py` | `openrouter` | https://openrouter.ai — one API key, 100+ hosted models |
| `litellm_proxy.py` | `litellm_proxy` | a self-hosted [LiteLLM proxy](https://docs.litellm.ai), which fans out to OpenAI / Anthropic / Bedrock / Vertex / Ollama / … |

Both are Apache-2.0, authored by Google, and are kept **byte-identical to the
upstream-recommended drop-in form**. Do not reformat them: `apply.sh` uses
`cmp -s` to tell our copy apart from one upstream might ship later.

## How they get into the container

Timesketch runs from a vendor image we do not build, so the providers have to
be written into the container's `site-packages` at runtime. That happens in a
prologue in `../docker-compose.yaml`, on every one of the four services that
run the Timesketch image:

```yaml
entrypoint: ["/bin/bash", "-c"]
command:
  - |
    mkdir -p /var/log/timesketch
    [ -r /opt/intact/llm_providers/apply.sh ] && bash /opt/intact/llm_providers/apply.sh; true
    exec /docker-entrypoint.sh timesketch-web
volumes:
  - ./llm_providers:/opt/intact/llm_providers:ro
```

`apply.sh` copies the two modules into `…/llms/providers/contrib/` and appends
a guarded import block to that package's `__init__.py`.

**Why a prologue and not `docker cp`:** `/opt/venv` is image-layer content —
there is no volume on it — so anything copied in is destroyed by the next
`compose up`. A prologue re-applies itself on every `up`, `--force-recreate`
**and** `docker restart`, which covers `install.sh`, both upgrade paths, and
the Settings → Timesketch restart without a line of code in any of them.

Nothing on the host is modified; the mount is read-only and every write lands
in the container's writable layer.

## Invariants — do not break these

- **`apply.sh` must never be able to stop Timesketch from starting.** No
  `set -e/-u/-o pipefail`, every path reaches `exit 0`, and the compose
  prologue guards it with `[ -r … ] && … ; true`.
- **Never make `apply.sh` the `entrypoint`.** On a partially-applied upgrade
  the host directory may not exist yet, and an entrypoint that isn't there
  means the container will not start at all.
- **Invoke it with `bash <path>`, never `./apply.sh`.** `install.sh`'s
  `fix_source_permissions` blanket-`chmod 644`s every tracked file, so the
  exec bit does not survive an install.
- **Never hardcode a Python version.** The image is on 3.14 today and has
  moved before. `apply.sh` resolves the package with `importlib.util.find_spec`
  and falls back to a `python*` glob.
- **Keep all three collision defences** in `apply.sh` — the `cmp -s` skip, the
  marker-grep append guard, and the per-import `try/except`.
  `LLMManager.register_provider()` raises `ValueError` on a duplicate `NAME`,
  and that exception propagates out of `timesketch.wsgi`: a double import does
  not degrade, it crash-loops all four containers.

## When upstream changes

Our providers are written against upstream's `interface.LLMProvider` and
`manager.LLMManager`, and we append to a file upstream owns. A Timesketch
version bump can break any of that.

`scripts/ci/check_timesketch_provider_drift.py` watches the relevant upstream
files and runs on every release build, warning (never failing) when they move.
After verifying the providers still work on a new Timesketch version:

```bash
python3 scripts/ci/check_timesketch_provider_drift.py --version <new-tag> --stamp
```

and commit the updated `scripts/ci/timesketch_provider_baseline.json`.

## Known limitations

- **The two providers differ in how they honour `response_schema`.**
  `litellm_proxy` sends a real `response_format` json_schema and parses the
  reply as JSON. `openrouter` does not send `response_format`; it wraps the
  model's raw text under the schema's first property. That is upstream's
  drop-in behaviour and is left as-is deliberately — for NL2Q, prefer LiteLLM
  or a model known to return clean JSON.
- **A partial upgrade that deselects `intact` gets neither the compose change
  nor this payload.** The result is inert (old compose, no prologue), not
  broken, but the providers will not appear until a full upgrade runs.

## Verifying

```bash
# Per-container decisions
docker exec intact_timesketch_web cat /var/log/timesketch/intact_llm_providers.log

# The actual proof: are they in the running registry?
docker exec intact_timesketch_web python3 -c "
import timesketch.lib.llms.providers as _p
from timesketch.lib.llms.providers import manager
print(sorted(n for n, _ in manager.LLMManager.get_providers()))"
```

Expect `openrouter` and `litellm_proxy` alongside upstream's own.
