#!/bin/bash
# Push backend source into the RUNNING container and restart it — the fast
# iteration loop, ~10s instead of a ~3min image rebuild.
#
# WHY THIS EXISTS. modules/nginx/html is bind-mounted, so frontend edits are
# live on refresh. modules/backend is NOT: it is baked into
# intact-backend:<tag> at build time, so a Python edit does nothing until the
# image is rebuilt. That asymmetry is a trap — the UI half of a change appears
# instantly and the backend half silently does not, which reads as "my fix
# didn't work" rather than "my fix isn't deployed".
#
# WHAT THIS IS NOT. The copy lives in the container's writable layer, so it
# survives `docker restart` but NOT `docker compose up`/`down`, which recreates
# from the image and silently reverts everything pushed here. The image stays
# stale either way, so a release still needs a real build. Use this to iterate;
# rebuild before you ship.
#
# Usage:
#   scripts/dev/push_backend.sh                  # push every changed-vs-HEAD .py
#   scripts/dev/push_backend.sh a.py b.py        # push specific files
#   scripts/dev/push_backend.sh --all            # push the whole backend tree
# ---------------------------------------------------------------------------
set -o pipefail

CONTAINER="${INTACT_BACKEND_CONTAINER:-intact_backend}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BACKEND_DIR="${SCRIPT_DIR}/modules/backend"

command -v docker >/dev/null 2>&1 || { echo "docker not found" >&2; exit 2; }
docker inspect "$CONTAINER" >/dev/null 2>&1 || {
    echo "container '$CONTAINER' is not running — start the platform first" >&2; exit 2; }

cd "$BACKEND_DIR" || exit 2

files=()
case "${1:-}" in
    --all)
        while IFS= read -r f; do files+=("$f"); done < <(find . -name '*.py' -not -path './__pycache__/*' | sed 's|^\./||')
        ;;
    "")
        # Everything that differs from HEAD — the usual case mid-change. Covers
        # unstaged, staged and untracked, so a brand-new module is not missed.
        while IFS= read -r f; do
            [[ "$f" == modules/backend/*.py ]] && files+=("${f#modules/backend/}")
        done < <(cd "$SCRIPT_DIR" && { git diff --name-only HEAD -- modules/backend
                                        git ls-files --others --exclude-standard -- modules/backend; } | sort -u)
        ;;
    *)
        for f in "$@"; do files+=("${f#modules/backend/}"); done
        ;;
esac

if [[ ${#files[@]} -eq 0 ]]; then
    echo "nothing changed under modules/backend — nothing to push"
    exit 0
fi

# Compile BEFORE copying. Pushing a file with a syntax error then restarting
# takes the backend down, and the error surfaces as a dead container rather
# than as the typo it is.
if ! python3 -m py_compile "${files[@]}" 2>/tmp/push_backend_compile.$$; then
    echo "REFUSING to push — syntax error:" >&2
    cat /tmp/push_backend_compile.$$ >&2
    rm -f /tmp/push_backend_compile.$$
    exit 1
fi
rm -f /tmp/push_backend_compile.$$

for f in "${files[@]}"; do
    if docker cp "$f" "${CONTAINER}:/app/${f}" 2>/dev/null; then
        echo "  → $f"
    else
        echo "  ! failed: $f" >&2
    fi
done

echo "restarting ${CONTAINER}..."
docker restart "$CONTAINER" >/dev/null || { echo "restart failed" >&2; exit 1; }

# Wait for health rather than guessing: the caller's next action is usually an
# API call, and hitting a still-booting backend reads as a broken change.
for _ in $(seq 1 30); do
    s="$(docker inspect -f '{{.State.Health.Status}}' "$CONTAINER" 2>/dev/null || echo unknown)"
    [[ "$s" == "healthy" ]] && { echo "${CONTAINER} healthy — ${#files[@]} file(s) live"; exit 0; }
    [[ "$s" == "unknown" ]] && { echo "${CONTAINER} restarted (no healthcheck) — ${#files[@]} file(s) live"; exit 0; }
    sleep 2
done
echo "WARNING: ${CONTAINER} did not report healthy — check: docker logs $CONTAINER" >&2
exit 1
