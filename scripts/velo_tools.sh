#!/bin/bash
# Intact.AI — add third-party Velociraptor tools to an appliance, including an
# air-gapped one.
#
# Velociraptor artifacts that run a third-party tool (Hayabusa, Sigcheck, an EZ
# parser, a YARA rule pack, an in-house binary, ...) fetch it from an internet
# URL unless the SERVER already stores it. An air-gapped box stores only the
# tools the default blueprints use, so every other artifact fails when it runs.
#
# GENERIC BY DESIGN. Nothing here carries a list of tools. `list` asks the
# running server which tools its own artifacts want and hasn't got, so newly
# imported artifacts and hand-made ones are covered the day they land, and
# `add` registers ANY file under ANY tool name the operator gives it.
#
#   on a machine WITH internet          on the AIR-GAPPED appliance
#   --------------------------          ---------------------------
#   velo_tools.sh list > missing.tsv    (carry missing.tsv over)
#   velo_tools.sh fetch missing.tsv \       velo_tools.sh import ./velo-tools
#       --out ./velo-tools              velo_tools.sh status
#   (carry ./velo-tools over)
#
# One tool, by hand, in one step:
#   velo_tools.sh add Hayabusa-2.14.0 /media/usb/hayabusa-2.14.0-win-x64.zip
#
# `add` records TOOL<TAB>FILE in data/tools/velo_tools.map, so a later
# `upgrade.sh --velo-refresh` re-registers under the tool's real NAME. Deleting
# the Velociraptor datastore volume drops every registration; the map is what
# makes putting them back one command instead of a memory exercise.
#
# Usage: scripts/velo_tools.sh <list|fetch|add|import|status> [args]
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS_DIR="${INTACT_TOOLS_DIR:-${SCRIPT_DIR}/data/tools}"
MAP_NAME="velo_tools.map"
VELO_CONTAINER="${VELO_CONTAINER:-intact_velociraptor}"
# Path INSIDE the Velociraptor container. data/tools is bind-mounted there.
CONTAINER_TOOLS_DIR="${CONTAINER_TOOLS_DIR:-/tools}"

log()  { printf '%s\n' "$*"; }
err()  { printf 'ERROR: %s\n' "$*" >&2; }

# Query the RUNNING server through its API. `query --config server.config.yaml`
# would start a second, local Velociraptor whose repository holds only the
# built-in artifacts -- it cannot see the ~400 curated ones loaded via
# --definitions, so it under-reports which tools are missing.
velo_vql() {
    docker exec "$VELO_CONTAINER" /velociraptor/velociraptor \
        --api_config /velociraptor/api.config.yaml query --format jsonl "$@"
}

require_container() {
    docker inspect "$VELO_CONTAINER" >/dev/null 2>&1 || {
        err "container ${VELO_CONTAINER} not found (is this the appliance?)"; return 1; }
    [[ "$(docker inspect -f '{{.State.Running}}' "$VELO_CONTAINER" 2>/dev/null)" == "true" ]] || {
        err "container ${VELO_CONTAINER} is not running"; return 1; }
}

# A tool name and a file name both end up inside a VQL string literal. Rather
# than escape them, refuse anything outside a conservative charset: a quote or
# a backslash in either would change the query, and no real tool name has one.
valid_token() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._+@-]*$ ]]; }

usage() {
    sed -n '2,31p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

# ---------------------------------------------------------------------------
# list — what the installed artifacts need and this server does not store
# ---------------------------------------------------------------------------
cmd_list() {
    require_container || return 1
    local out
    out="$(velo_vql \
        "LET stored <= SELECT name FROM inventory() WHERE serve_locally AND hash" \
        "SELECT * FROM foreach(row={SELECT name AS Artifact, tools FROM artifact_definitions() WHERE tools}, query={SELECT name AS Tool, url AS Url, Artifact FROM foreach(row=tools) WHERE NOT name IN stored.name}) ORDER BY Tool")" || {
        err "could not query the server"; return 1; }

    # TSV: one row per tool, artifacts that want it collapsed into one column.
    # Made for `fetch` to read and for a human to edit before carrying it over.
    printf '%s' "$out" | python3 -c '
import json, sys
tools = {}
for line in sys.stdin:
    if not line.strip():
        continue
    r = json.loads(line)
    t = tools.setdefault(r["Tool"], {"url": r.get("Url") or "", "arts": []})
    t["arts"].append(r.get("Artifact", ""))
    if not t["url"]:
        t["url"] = r.get("Url") or ""
print("# TOOL\tURL\tARTIFACTS (delete the rows you do not need)")
for name in sorted(tools):
    t = tools[name]
    print("%s\t%s\t%s" % (name, t["url"], ",".join(sorted(set(t["arts"])))))
print("# %d tool(s) missing" % len(tools), file=sys.stderr)
'
}

# ---------------------------------------------------------------------------
# fetch — run where there IS internet; downloads into a carry folder
# ---------------------------------------------------------------------------
cmd_fetch() {
    local listfile="" out=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --out) out="${2:-}"; shift 2 ;;
            -h|--help) usage 0 ;;
            *) listfile="$1"; shift ;;
        esac
    done
    [[ -n "$listfile" ]] || { err "usage: velo_tools.sh fetch <list.tsv|-> --out DIR"; return 1; }
    [[ -n "$out" ]] || { err "--out DIR is required"; return 1; }
    [[ "$listfile" == "-" || -f "$listfile" ]] || { err "no such file: $listfile"; return 1; }
    mkdir -p "$out" || return 1

    local ok=0 skipped=0 failed=0 line tool url rest fname
    while IFS= read -r line; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        # Split on TABs by hand: `read -r tool url rest` with IFS=tab treats
        # repeated tabs as one separator, so a row whose URL is empty (a vendor
        # tool with no public download) shifted its artifact list into the URL.
        [[ "$line" == *$'\t'* ]] || continue
        tool="${line%%$'\t'*}"; rest="${line#*$'\t'}"; url="${rest%%$'\t'*}"
        if [[ -z "${url:-}" ]]; then
            log "  no public URL, get it from the vendor: ${tool}"
            skipped=$((skipped + 1)); continue
        fi
        fname="$(basename "${url%%\?*}")"
        if curl -fL --retry 3 --connect-timeout 30 -o "${out}/${fname}" "$url"; then
            # The map is what makes the tool land under its REAL name on the
            # other side; the file name alone is not enough to register with.
            printf '%s\t%s\n' "$tool" "$fname" >> "${out}/${MAP_NAME}"
            log "  fetched ${tool} -> ${fname}"
            ok=$((ok + 1))
        else
            err "download failed: ${tool} (${url})"
            rm -f "${out}/${fname}"
            failed=$((failed + 1))
        fi
    done < <([[ "$listfile" == "-" ]] && cat || cat "$listfile")

    log "fetch: ${ok} downloaded, ${skipped} without a public URL, ${failed} failed"
    log "carry ${out} (files + ${MAP_NAME}) to the appliance, then: velo_tools.sh import ${out}"
    (( failed )) && return 1
    return 0
}

# ---------------------------------------------------------------------------
# add — register ONE file under ONE exact tool name. No network.
# ---------------------------------------------------------------------------
cmd_add() {
    local tool="${1:-}" file="${2:-}"
    [[ -n "$tool" && -n "$file" ]] || { err "usage: velo_tools.sh add <TOOL_NAME> <FILE>"; return 1; }
    # Check the arguments BEFORE reaching for docker, so a bad name fails the
    # same way whether or not this box is an appliance.
    valid_token "$tool" || { err "tool name has characters that are not allowed: ${tool}"; return 1; }
    [[ -f "$file" ]] || { err "no such file: ${file}"; return 1; }

    local base; base="$(basename "$file")"
    valid_token "$base" || { err "file name has characters that are not allowed: ${base}"; return 1; }
    require_container || return 1

    mkdir -p "$TOOLS_DIR" || return 1
    # Keep the file where the container can read it. Copying to itself is fine
    # and means `add` works both for a carried file and for one already staged.
    if [[ "$(cd "$(dirname "$file")" && pwd)/${base}" != "${TOOLS_DIR}/${base}" ]]; then
        cp -f "$file" "${TOOLS_DIR}/${base}" || { err "could not copy into ${TOOLS_DIR}"; return 1; }
        chmod 644 "${TOOLS_DIR}/${base}" 2>/dev/null || true
    fi

    local res
    res="$(velo_vql "SELECT inventory_add(tool='${tool}', serve_locally=TRUE, file='${CONTAINER_TOOLS_DIR}/${base}', filename='${base}', accessor='file') AS r FROM scope()" 2>&1)"
    if ! grep -q '"r"' <<<"$res"; then
        err "registration failed for ${tool}: $(head -c 200 <<<"$res")"
        return 1
    fi

    # Record it, replacing any earlier line for the same tool.
    local map="${TOOLS_DIR}/${MAP_NAME}" tmp
    tmp="$(mktemp)"
    # Drop any earlier line for this tool (awk, not grep -P: no GNU-only flags).
    [[ -f "$map" ]] && awk -F'\t' -v t="$tool" '$1 != t' "$map" > "$tmp" 2>/dev/null
    printf '%s\t%s\n' "$tool" "$base" >> "$tmp"
    mv "$tmp" "$map" && chmod 644 "$map" 2>/dev/null || true

    log "registered ${tool} -> ${base}"
}

# ---------------------------------------------------------------------------
# import — replay a carry folder's map (or the appliance's own). No network.
# ---------------------------------------------------------------------------
cmd_import() {
    local dir="${1:-$TOOLS_DIR}"
    [[ -d "$dir" ]] || { err "no such directory: ${dir}"; return 1; }
    local map="${dir}/${MAP_NAME}"
    [[ -f "$map" ]] || { err "no ${MAP_NAME} in ${dir} — add tools one at a time with: velo_tools.sh add <TOOL> <FILE>"; return 1; }
    require_container || return 1

    local ok=0 failed=0 line tool fname
    while IFS= read -r line; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        [[ "$line" == *$'\t'* ]] || continue
        tool="${line%%$'\t'*}"; fname="${line#*$'\t'}"
        if [[ ! -f "${dir}/${fname}" ]]; then
            err "missing file for ${tool}: ${dir}/${fname}"
            failed=$((failed + 1)); continue
        fi
        if cmd_add "$tool" "${dir}/${fname}"; then ok=$((ok + 1)); else failed=$((failed + 1)); fi
    done < "$map"

    log "import: ${ok} registered, ${failed} failed"
    (( failed )) && return 1
    return 0
}

# ---------------------------------------------------------------------------
# status — what this server stores, and how many tools are still missing
# ---------------------------------------------------------------------------
cmd_status() {
    require_container || return 1
    log "Stored on this server (served to endpoints, no internet needed):"
    velo_vql "SELECT name, filename FROM inventory() WHERE serve_locally AND hash ORDER BY name" \
        | python3 -c "
import json,sys
n=0
for l in sys.stdin:
    if l.strip():
        d=json.loads(l); n+=1; print(f\"  {d.get('name','')}  <-  {d.get('filename','')}\")
print(f'  ({n} tool(s))')"
    local missing
    missing="$(cmd_list 2>/dev/null | grep -cvE '^#|^$')"
    log "Missing (an artifact wants them, this server has not got them): ${missing:-0}"
    log "List them with: $(basename "${BASH_SOURCE[0]}") list"
}

case "${1:-}" in
    list)   shift; cmd_list "$@" ;;
    fetch)  shift; cmd_fetch "$@" ;;
    add)    shift; cmd_add "$@" ;;
    import) shift; cmd_import "$@" ;;
    status) shift; cmd_status "$@" ;;
    -h|--help|help|"") usage 0 ;;
    *) err "unknown command: $1"; usage 2 ;;
esac
