#!/bin/bash
# Install IntactAI's contrib LLM providers into the vendor Timesketch image.
#
# Runs INSIDE the Timesketch container, from the `command:` prologue in
# modules/timesketch/docker-compose.yaml, before /docker-entrypoint.sh.
#
# CONTRACT: this script MUST NOT be able to stop Timesketch from starting.
# No `set -e`, no `set -u`, no `set -o pipefail`; every path reaches `exit 0`.
# If anything at all goes wrong we log it and Timesketch boots unmodified —
# an unavailable LLM provider is an inconvenience, a container that will not
# start is an outage.
#
# Why a start-up prologue and not `docker cp`: /opt/venv is image-layer
# content (there is no volume on it), so anything copied in is destroyed by
# the next `compose up`/recreate. A prologue re-applies itself on every up,
# force-recreate AND docker restart, which covers install.sh, both upgrade
# paths, and the Settings->Timesketch restart with no code in any of them.
#
# What it does, on every start:
#   1. locates the installed timesketch providers package (never hardcodes a
#      Python version — the image is on 3.14 today and has moved before)
#   2. copies our provider modules into providers/contrib/, but NEVER over a
#      file upstream ships itself
#   3. appends guarded import lines to providers/__init__.py, once
#
# Everything lands in the container's writable layer only. Nothing on the
# host is touched — the source directory is mounted read-only.

SRC="${INTACT_LLM_PROVIDERS_SRC:-/opt/intact/llm_providers}"
LOG="${INTACT_LLM_PROVIDERS_LOG:-/var/log/timesketch/intact_llm_providers.log}"
PROVIDERS="${INTACT_LLM_PROVIDERS_LIST:-openrouter litellm_proxy}"
MARK="# --- intact.ai: contrib LLM providers ---"
MARK_END="# --- intact.ai: end contrib LLM providers ---"

mkdir -p "$(dirname "$LOG")" 2>/dev/null

say() {
    # stdout so `docker logs` shows it during boot; file so it survives on the
    # timesketch_logs volume for post-hoc inspection long after the fact.
    printf '%s intact-llm-providers: %s\n' \
        "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" | tee -a "$LOG" 2>/dev/null
}

# --- 1. locate the providers package -----------------------------------------
#
# find_spec, NOT `import timesketch.lib.llms.providers`: importing the
# providers package executes every provider module (and drags in flask),
# which is exactly the thing that might be broken. find_spec("timesketch")
# resolves the top-level package location without executing anything under it.
PKG="${INTACT_LLM_PROVIDERS_PKG:-}"

if [ -z "$PKG" ]; then
    PKG="$(python3 -c 'import importlib.util, os, sys
spec = importlib.util.find_spec("timesketch")
if not spec or not spec.origin:
    sys.exit(1)
print(os.path.join(os.path.dirname(spec.origin), "lib", "llms", "providers"))' 2>/dev/null)"
fi

# Fallback for the case where find_spec fails but the tree is where it has
# always been. Globbed, never a literal python3.NN.
if [ -z "$PKG" ] || [ ! -d "$PKG" ]; then
    PKG="$(ls -d /opt/venv/lib/python*/site-packages/timesketch/lib/llms/providers 2>/dev/null | head -1)"
fi

if [ -z "$PKG" ] || [ ! -f "$PKG/__init__.py" ] || [ ! -d "$PKG/contrib" ]; then
    say "could not locate the timesketch providers package (looked at '${PKG:-<none>}') — skipping, Timesketch starts unmodified"
    exit 0
fi
say "providers package: $PKG"

# --- 2. copy the provider modules --------------------------------------------
INSTALLED=""
for name in $PROVIDERS; do
    src="$SRC/${name}.py"
    dst="$PKG/contrib/${name}.py"

    if [ ! -r "$src" ]; then
        # Normal on a partially-applied upgrade: the compose file arrived with
        # the bind mount but the payload did not, so docker mounted an empty
        # directory. Not an error — just nothing to do.
        say "source missing: $src — skipping ${name}"
        continue
    fi

    if [ -e "$dst" ]; then
        if cmp -s "$src" "$dst"; then
            say "${name}: already present and identical — no write"
            INSTALLED="$INSTALLED $name"
            continue
        fi
        # A DIFFERING file at that path means upstream now ships its own
        # provider under this name (the container's writable layer starts
        # empty, so it cannot be a leftover of ours). Do not clobber it, and
        # do not add our import line — upstream's __init__ already owns it.
        # Clobbering would also risk a duplicate NAME, and
        # LLMManager.register_provider() raises ValueError on duplicates,
        # which would abort the import of timesketch.wsgi entirely.
        say "${name}: upstream ships its own contrib/${name}.py — leaving it alone, NOT installing ours"
        continue
    fi

    if cp "$src" "$dst" 2>/dev/null; then
        say "${name}: installed -> $dst"
        INSTALLED="$INSTALLED $name"
    else
        say "${name}: copy failed (read-only site-packages?) — skipping"
    fi
done

if [ -z "$INSTALLED" ]; then
    say "no providers installed — leaving __init__.py untouched"
    exit 0
fi

# --- 3. register them by appending guarded imports ----------------------------
if grep -qF "$MARK" "$PKG/__init__.py" 2>/dev/null; then
    say "import block already present in __init__.py — no append"
else
    # APPEND ONLY, at end of file. Upstream's own imports run first and are
    # preserved verbatim, so an upstream change to this file survives us.
    #
    # Each import is individually guarded. register_provider() raises
    # ValueError on a duplicate NAME, and a provider module that no longer
    # matches the interface raises at import — either would abort the import
    # of timesketch.lib.llms.providers, and therefore of timesketch.wsgi,
    # i.e. take the whole app down. The broad `except Exception` is
    # deliberate; BaseException is not caught, so KeyboardInterrupt and
    # SystemExit still behave normally.
    #
    # Logged at info, not warning: a provider the operator never configured
    # being unavailable is not a problem worth colouring Timesketch's logs.
    {
        printf '\n\n'
        echo "$MARK"
        echo 'import logging as _intact_logging'
        echo '_intact_log = _intact_logging.getLogger("timesketch.llm.manager")'
        for name in $INSTALLED; do
            # Unquoted heredoc so $name interpolates. Note %s is literal here —
            # heredocs do no printf formatting.
            cat <<EOF
try:
    from timesketch.lib.llms.providers.contrib import $name  # noqa: F401
except Exception as _intact_exc:  # pragma: no cover
    _intact_log.info(
        "intact.ai contrib LLM provider %s not registered: %s: %s",
        "$name", type(_intact_exc).__name__, _intact_exc)
EOF
        done
        echo "$MARK_END"
    } >> "$PKG/__init__.py" 2>/dev/null \
        && say "appended guarded imports for:$INSTALLED" \
        || say "could not append to __init__.py — providers copied but NOT imported"
fi

# Today's image ships timestamp-based .pyc (verified: flags=0), so the append
# invalidates the cache on its own. An image built with
# --invalidation-mode unchecked-hash would NOT revalidate and our edit would
# be silently ignored — a very hard bug to find. Dropping the caches costs one
# recompile at startup and removes the whole failure mode.
rm -rf "$PKG/__pycache__" "$PKG/contrib/__pycache__" 2>/dev/null

exit 0
