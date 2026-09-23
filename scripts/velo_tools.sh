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
# Prove an endpoint really gets a tool (needs one enrolled client):
#   velo_tools.sh test --tool etl2pcapng
#
# On a box WITH internet, one tool by name -- no URL to copy:
#   velo_tools.sh install Takajo-2.5.0
#
# One tool, by hand, in one step:
#   velo_tools.sh add Hayabusa-2.14.0 /media/usb/hayabusa-2.14.0-win-x64.zip
#
# `add` records TOOL<TAB>FILE in data/tools/velo_tools.map, so a later
# `upgrade.sh --velo-refresh` re-registers under the tool's real NAME. Deleting
# the Velociraptor datastore volume drops every registration; the map is what
# makes putting them back one command instead of a memory exercise.
#
# Usage: scripts/velo_tools.sh <list|install|fetch|add|import|status|test|selftest> [args]
#        add/import take --force to register a file whose hash an artifact pins
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
    # Print the header comment, however long it grows -- a fixed line range
    # silently truncated the help the moment the header gained a line, which
    # cut off the Usage line itself.
    awk 'NR > 1 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "${BASH_SOURCE[0]}"
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
        "SELECT * FROM foreach(row={SELECT name AS Artifact, tools FROM artifact_definitions() WHERE tools}, query={SELECT name AS Tool, url AS Url, expected_hash AS Expected, Artifact FROM foreach(row=tools) WHERE NOT name IN stored.name}) ORDER BY Tool")" || {
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
    t = tools.setdefault(r["Tool"], {"url": r.get("Url") or "", "sha": r.get("Expected") or "", "arts": []})
    t["arts"].append(r.get("Artifact", ""))
    if not t["url"]:
        t["url"] = r.get("Url") or ""
    if not t["sha"]:
        t["sha"] = r.get("Expected") or ""
print("# TOOL\tURL\tSHA256 the artifact expects (empty = any)\tARTIFACTS (delete rows you do not need)")
for name in sorted(tools):
    t = tools[name]
    print("%s\t%s\t%s\t%s" % (name, t["url"], t["sha"], ",".join(sorted(set(t["arts"])))))
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

    local ok=0 skipped=0 failed=0 line tool url rest fname want_sha got_sha
    while IFS= read -r line; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        # Split on TABs by hand: `read -r tool url rest` with IFS=tab treats
        # repeated tabs as one separator, so a row whose URL is empty (a vendor
        # tool with no public download) shifted its artifact list into the URL.
        [[ "$line" == *$'\t'* ]] || continue
        tool="${line%%$'\t'*}"; rest="${line#*$'\t'}"; url="${rest%%$'\t'*}"
        rest="${rest#*$'\t'}"; want_sha="${rest%%$'\t'*}"
        [[ "$want_sha" == "$url" ]] && want_sha=""   # a 3-column row (no hash column)
        if [[ -z "${url:-}" ]]; then
            log "  no public URL, get it from the vendor: ${tool}"
            skipped=$((skipped + 1)); continue
        fi
        fname="$(basename "${url%%\?*}")"
        if curl -fL --retry 3 --connect-timeout 30 -o "${out}/${fname}" "$url"; then
            # The map is what makes the tool land under its REAL name on the
            # other side; the file name alone is not enough to register with.
            # One line per tool: fetching into the same folder twice used to
            # append a second line, so import then registered it twice.
            local fmap="${out}/${MAP_NAME}" ftmp
            ftmp="$(mktemp)" || return 1
            [[ -f "$fmap" ]] && grep -v -P "^\Q${tool}\E\t" "$fmap" > "$ftmp" 2>/dev/null
            printf '%s\t%s\n' "$tool" "$fname" >> "$ftmp"
            mv "$ftmp" "$fmap"
            # An artifact may pin the tool's sha256. Downloading "the latest"
            # of a pinned tool gives a file the endpoint will refuse, and the
            # refusal happens at collection time, at the customer site.
            if [[ -n "$want_sha" ]]; then
                got_sha="$(sha256sum < "${out}/${fname}" | cut -d' ' -f1)"
                if [[ "$got_sha" != "$want_sha" ]]; then
                    err "hash mismatch for ${tool}: the artifact expects ${want_sha}, this download is ${got_sha}"
                    err "  the URL now serves a different version — get the pinned one, or update the artifact"
                    failed=$((failed + 1))
                    continue
                fi
            fi
            log "  fetched ${tool} -> ${fname}${want_sha:+ (hash matches)}"
            ok=$((ok + 1))
        else
            err "download failed: ${tool} (${url})"
            rm -f "${out}/${fname}"
            failed=$((failed + 1))
        fi
    done < <([[ "$listfile" == "-" ]] && cat || cat "$listfile")

    # AN EMPTY CARRY FOLDER IS NOT A SUCCESS. A list that matched nothing (a grep
    # for tools this box already holds, a file with only its header) used to end
    # with "carry <dir> to the appliance" — and the operator found out at the
    # air-gapped site that the USB was empty.
    if (( ok == 0 && skipped == 0 && failed == 0 )); then
        err "nothing to fetch: no tool rows in ${listfile}"
        err "  every row was blank or a comment. Check what your filter matched:"
        err "    grep -c . ${listfile}   # rows, including the '# N tool(s) missing' header"
        err "  A tool this server already holds is not in 'list', so a filter naming one matches nothing."
        return 1
    fi
    log "fetch: ${ok} downloaded, ${skipped} without a public URL, ${failed} failed"
    (( ok )) && log "carry ${out} (files + ${MAP_NAME}) to the appliance, then: velo_tools.sh import ${out}"
    (( failed )) && return 1
    return 0
}

# ---------------------------------------------------------------------------
# add — register ONE file under ONE exact tool name. No network.
# ---------------------------------------------------------------------------
# The sha256 an artifact pins for this tool, or empty. Registering a file that
# does not match it succeeds here and fails on the endpoint, so `add` checks.
expected_hash_for() {
    local tool="$1"
    velo_vql "SELECT * FROM foreach(row={SELECT tools FROM artifact_definitions() WHERE tools}, query={SELECT expected_hash AS h FROM foreach(row=tools) WHERE name = '${tool}' AND expected_hash}) LIMIT 1" 2>/dev/null \
        | python3 -c 'import sys,json
for l in sys.stdin:
    l=l.strip()
    if l:
        print(json.loads(l).get("h","") or "")
        break' 2>/dev/null
}

stored_hash_for() {
    # The sha256 the SERVER already holds for a tool, or "" when it holds none.
    local tool="$1"
    velo_vql "SELECT hash FROM inventory() WHERE name = '${tool}' AND serve_locally AND hash LIMIT 1" 2>/dev/null \
        | python3 -c 'import sys,json
for l in sys.stdin:
    l=l.strip()
    if l:
        print(json.loads(l).get("hash","") or "")
        break' 2>/dev/null
}


cmd_add() {
    local force=0
    local args=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --force) force=1; shift ;;
            *) args+=("$1"); shift ;;
        esac
    done
    set -- "${args[@]:-}"
    local tool="${1:-}" file="${2:-}"
    [[ -n "$tool" && -n "$file" ]] || { err "usage: velo_tools.sh add <TOOL_NAME> <FILE>"; return 1; }
    # Check the arguments BEFORE reaching for docker, so a bad name fails the
    # same way whether or not this box is an appliance.
    valid_token "$tool" || { err "tool name has characters that are not allowed: ${tool}"; return 1; }
    [[ -f "$file" ]] || { err "no such file: ${file}"; return 1; }

    local base; base="$(basename "$file")"
    valid_token "$base" || { err "file name has characters that are not allowed: ${base}"; return 1; }
    require_container || return 1

    local want_sha got_sha
    want_sha="$(expected_hash_for "$tool")"
    if [[ -n "$want_sha" ]]; then
        got_sha="$(sha256sum < "$file" | cut -d' ' -f1)"
        if [[ "$got_sha" != "$want_sha" ]]; then
            if (( force )); then
                log "  WARNING: ${tool} hash does not match what the artifact expects — registering anyway (--force)"
            else
                err "hash mismatch for ${tool}"
                err "  the artifact expects: ${want_sha}"
                err "  this file is:         ${got_sha}"
                err "  endpoints would refuse it. Get the pinned version, or re-run with --force."
                return 1
            fi
        fi
    fi

    mkdir -p "$TOOLS_DIR" || return 1
    # Only now, with the file accepted, put it where the container can read it.
    # Copying a file that is already there onto itself is skipped, so `add`
    # works for a carried file and for one already staged.
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
# install — name a tool, get it. Only on a box WITH internet.
#
# The URL comes from the artifact that wants the tool, so there is no URL to
# copy by hand and no version to guess -- the two things that go wrong when an
# operator assembles the command themselves.
# ---------------------------------------------------------------------------
cmd_install() {
    local force_arg="" tools=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --force) force_arg="--force"; shift ;;
            -h|--help) usage 0 ;;
            *) tools+=("$1"); shift ;;
        esac
    done
    [[ ${#tools[@]} -gt 0 ]] || { err "usage: velo_tools.sh install <TOOL_NAME> [TOOL_NAME ...]"; return 1; }
    require_container || return 1

    local tmp; tmp="$(mktemp -d)" || return 1
    local ok=0 failed=0 held=0 tool url fname
    for tool in "${tools[@]}"; do
        valid_token "$tool" || { err "tool name has characters that are not allowed: ${tool}"; failed=$((failed + 1)); continue; }
        url="$(velo_vql "SELECT * FROM foreach(row={SELECT tools FROM artifact_definitions() WHERE tools}, query={SELECT url AS u FROM foreach(row=tools) WHERE name = '${tool}' AND url}) LIMIT 1" 2>/dev/null \
            | python3 -c 'import sys,json
l=sys.stdin.readline()
print(json.loads(l).get("u","") if l.strip() else "")' 2>/dev/null)"
        if [[ -z "$url" ]]; then
            err "no download URL known for '${tool}'"
            err "  either no artifact asks for it, or it has no public download (a vendor installer)."
            err "  Get the file yourself, then: velo_tools.sh add ${tool} <file>"
            failed=$((failed + 1)); continue
        fi
        # ALREADY DONE IS NOT A REASON TO DOWNLOAD AGAIN. Re-running install at
        # a site (or after an upgrade) used to re-fetch every tool over the
        # customer's link and re-register the same bytes. Skip when the server
        # already holds it — and, when the artifact pins a hash, only when what
        # it holds is that file. --force re-downloads regardless.
        if [[ -z "$force_arg" ]]; then
            local have want
            have="$(stored_hash_for "$tool")"
            want="$(expected_hash_for "$tool")"
            if [[ -n "$have" && ( -z "$want" || "$have" == "$want" ) ]]; then
                log "${tool}: already stored on the server — skipping (use --force to download again)"
                held=$((held + 1)); continue
            fi
            if [[ -n "$have" && -n "$want" && "$have" != "$want" ]]; then
                log "${tool}: stored copy does not match the hash the artifact pins — downloading the right one"
            fi
        fi
        fname="$(basename "${url%%\?*}")"
        log "${tool}: downloading ${url}"
        if ! curl -fL --retry 3 --connect-timeout 30 --progress-bar -o "${tmp}/${fname}" "$url"; then
            err "download failed for ${tool} (${url})"
            failed=$((failed + 1)); continue
        fi
        if cmd_add ${force_arg:+$force_arg} "$tool" "${tmp}/${fname}"; then ok=$((ok + 1)); else failed=$((failed + 1)); fi
    done
    rm -rf "$tmp"

    # Say what actually happened: reporting a skipped tool as "added" made a
    # re-run read as if it had downloaded everything again.
    log "install: ${ok} added, ${held} already stored, ${failed} failed"
    (( failed )) && return 1
    return 0
}

# ---------------------------------------------------------------------------
# import — replay a carry folder's map (or the appliance's own). No network.
# ---------------------------------------------------------------------------
name_from_inventory() {
    # The tool name the SHIPPED inventory gives a file, or "" — the same
    # pattern -> name table `upgrade.sh --velo-refresh` uses. This is what makes
    # `import data/tools` able to put the installer's own tools back: they were
    # staged by the installer and are not in velo_tools.map.
    local base="$1"
    INTACT_TOOLS_YAML="${INTACT_TOOLS_YAML:-${SCRIPT_DIR}/data/tools_inventory.yaml}" \
    INTACT_TOOL_FILE="$base" python3 - <<'PY' 2>/dev/null
import os, re
try:
    import yaml
except Exception:
    raise SystemExit(0)
path = os.environ["INTACT_TOOLS_YAML"]
name = os.environ["INTACT_TOOL_FILE"]
try:
    inv = (yaml.safe_load(open(path, encoding="utf-8")) or {}).get("velociraptor_inventory") or []
except Exception:
    raise SystemExit(0)
for entry in inv:
    tool, pat = entry.get("tool_name"), entry.get("file_pattern")
    if not tool or not pat:
        continue
    try:
        if re.match(pat, name):
            print(tool)
            break
    except re.error:
        continue
PY
}

cmd_import() {
    local force_arg=""
    local args=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --force) force_arg="--force"; shift ;;
            *) args+=("$1"); shift ;;
        esac
    done
    set -- "${args[@]:-}"
    local dir="${1:-$TOOLS_DIR}"
    [[ -d "$dir" ]] || { err "no such directory: ${dir}"; return 1; }
    local map="${dir}/${MAP_NAME}"
    [[ -f "$map" ]] || { err "no ${MAP_NAME} in ${dir} — add tools one at a time with: velo_tools.sh add <TOOL> <FILE>"; return 1; }
    require_container || return 1

    local ok=0 failed=0 line tool fname
    local -a mapped=() bad_lines=()
    while IFS= read -r line; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        # A line with no TAB used to be skipped in silence, so a map written with
        # spaces registered NOTHING and still reported success.
        if [[ "$line" != *$'\t'* ]]; then
            bad_lines+=("$line")
            continue
        fi
        tool="${line%%$'\t'*}"; fname="${line#*$'\t'}"
        mapped+=("$fname")
        if [[ ! -f "${dir}/${fname}" ]]; then
            err "missing file for ${tool}: ${dir}/${fname}"
            failed=$((failed + 1)); continue
        fi
        if cmd_add ${force_arg:+$force_arg} "$tool" "${dir}/${fname}"; then ok=$((ok + 1)); else failed=$((failed + 1)); fi
    done < "$map"

    # A carried file the map does not name is NOT registered — say so. A folder
    # reused between carries keeps its old map, so new files dropped into it were
    # silently left out while the command reported success.
    local -a unmapped=() f base
    for f in "${dir}"/*; do
        [[ -f "$f" ]] || continue
        base="$(basename "$f")"
        [[ "$base" == "$MAP_NAME" ]] && continue
        local m seen=0
        for m in ${mapped[@]+"${mapped[@]}"}; do [[ "$m" == "$base" ]] && { seen=1; break; }; done
        (( seen )) || unmapped+=("$base")
    done
    if (( ${#bad_lines[@]} )); then
        err "${#bad_lines[@]} line(s) in ${MAP_NAME} have no TAB between the tool name and the file, and were skipped:"
        for f in "${bad_lines[@]}"; do err "  ${f}"; done
        failed=$((failed + ${#bad_lines[@]}))
    fi
    # A file the map does not name may still be one the SHIPPED inventory knows —
    # every tool the installer staged is in that table and in no map. Falling back
    # to it is what makes `import data/tools` put the default tools back after the
    # Docker volumes were deleted; before this it left them unregistered.
    local -a unnamed=()
    for f in ${unmapped[@]+"${unmapped[@]}"}; do
        tool="$(name_from_inventory "$f")"
        if [[ -n "$tool" ]]; then
            if cmd_add ${force_arg:+$force_arg} "$tool" "${dir}/${f}"; then ok=$((ok + 1)); else failed=$((failed + 1)); fi
        else
            unnamed+=("$f")
        fi
    done
    if (( ${#unnamed[@]} )); then
        log "  WARNING: ${#unnamed[@]} file(s) here are named by neither ${MAP_NAME} nor the shipped inventory, and were NOT registered:"
        for f in "${unnamed[@]}"; do log "    ${f}"; done
        log "    add each with: $(basename "${BASH_SOURCE[0]}") add <TOOL> ${dir}/<FILE>"
    fi
    log "import: ${ok} registered, ${failed} failed"
    (( failed )) && return 1
    return 0
}

# ---------------------------------------------------------------------------
# selftest — run the whole chain on this box and check every step.
#
# Picks a tool the server is missing, installs it, then proves the three things
# that actually matter: it is stored, the server really serves those bytes over
# the endpoint-facing URL, and (if a client is enrolled) an endpoint downloads
# it. Anything it cannot prove is reported as SKIP, never as a pass.
# ---------------------------------------------------------------------------
cmd_selftest() {
    local tool=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --tool) tool="${2:-}"; shift 2 ;;
            -h|--help) usage 0 ;;
            *) err "unknown argument: $1"; return 1 ;;
        esac
    done
    require_container || return 1
    local pass=0 fail=0 skip=0
    _ok()   { log "  PASS  $*"; pass=$((pass + 1)); }
    _bad()  { err "  FAIL  $*"; fail=$((fail + 1)); }
    _skip() { log "  SKIP  $*"; skip=$((skip + 1)); }

    log "1. what the server is missing"
    local listing missing
    listing="$(cmd_list 2>/dev/null)" || { _bad "could not list missing tools"; return 1; }
    missing="$(grep -cvE '^#|^$' <<<"$listing")"
    log "   ${missing} tool(s) missing"
    [[ "$missing" -gt 0 ]] && _ok "list works" || _skip "nothing missing to test with"

    # A tool with a public URL, so `install` has something to fetch.
    [[ -n "$tool" ]] || tool="$(awk -F'\t' '$1 !~ /^#/ && $2 != "" {print $1; exit}' <<<"$listing")"
    [[ -n "$tool" ]] || { _skip "no missing tool has a public URL — pass --tool NAME"; log "SUMMARY: ${pass} pass, ${fail} fail, ${skip} skip"; return 0; }

    log "2. install '${tool}' by name (download + register)"
    if cmd_install "$tool" >/dev/null 2>&1; then _ok "installed ${tool}"; else _bad "could not install ${tool}"; fi

    log "3. is it stored on the server?"
    local row hash filename
    row="$(velo_vql "SELECT filename, hash, serve_url FROM inventory() WHERE name = '${tool}' AND serve_locally AND hash" 2>/dev/null | head -1)"
    hash="$(printf '%s' "$row" | python3 -c 'import sys,json
l=sys.stdin.readline(); print(json.loads(l).get("hash","") if l.strip() else "")' 2>/dev/null)"
    filename="$(printf '%s' "$row" | python3 -c 'import sys,json
l=sys.stdin.readline(); print(json.loads(l).get("filename","") if l.strip() else "")' 2>/dev/null)"
    [[ -n "$hash" ]] && _ok "stored as ${filename} (${hash:0:12}…)" || _bad "not stored"

    log "4. does the server actually serve those bytes?"
    local url served
    url="$(printf '%s' "$row" | python3 -c 'import sys,json
l=sys.stdin.readline(); print(json.loads(l).get("serve_url","") if l.strip() else "")' 2>/dev/null)"
    if [[ -n "$url" ]]; then
        served="$(curl -sk --max-time 120 "$url" | sha256sum | cut -d' ' -f1)"
        if [[ "$served" == "$hash" ]]; then _ok "downloaded from ${url%%/public/*}/public/… and the hash matches"
        else _bad "served bytes do not match the stored hash (${served:0:12}… vs ${hash:0:12}…)"; fi
    else
        _bad "no serve_url — endpoints would have nowhere to fetch it from"
    fi

    log "5. does an endpoint download it?"
    local client
    client="$(velo_vql "SELECT client_id FROM clients() ORDER BY last_seen_at DESC LIMIT 1" 2>/dev/null \
        | python3 -c 'import sys,json
l=sys.stdin.readline(); print(json.loads(l).get("client_id","") if l.strip() else "")' 2>/dev/null)"
    if [[ -z "$client" ]]; then
        _skip "no endpoint is enrolled — install a client, then: velo_tools.sh test --tool ${tool}"
    else
        cmd_test --tool "$tool" --client "$client" >/dev/null 2>&1
        case "$?" in
            0) _ok "endpoint ${client} downloaded ${tool}" ;;
            # 2 = the endpoint is offline, so the collection is only queued. A
            # step that cannot run is a SKIP, never a fail (and never a pass).
            2) _skip "endpoint ${client} was last seen $(human_age "$(client_age_seconds "$client")") — start a live client, then: velo_tools.sh test --tool ${tool}" ;;
            *) _bad "endpoint ${client} did not get ${tool} — run: velo_tools.sh test --tool ${tool}" ;;
        esac
    fi

    log ""
    log "SUMMARY: ${pass} pass, ${fail} fail, ${skip} skip"
    (( fail )) && return 1
    return 0
}

# ---------------------------------------------------------------------------
# test — make an ENDPOINT download a tool from this server, and say if it did
#
# Registering a tool and serving it are two different things, and only the
# endpoint proves the second. Generic.Utils.FetchBinary is the helper every
# tool-using artifact calls internally, so collecting it is the smallest
# possible end-to-end check: no forensic artifact runs, nothing is collected
# off the machine.
# ---------------------------------------------------------------------------
# How long after an endpoint was last seen a tool test is still worth running.
# Beyond this the client is offline: the collection is queued for whenever it
# comes back, so the test can neither pass nor fail.
VELO_ENDPOINT_MAX_AGE="${VELO_ENDPOINT_MAX_AGE:-300}"

client_age_seconds() {
    # Seconds since this endpoint last talked to the server, or "" if unknown.
    local c="$1" seen
    seen="$(velo_vql "SELECT last_seen_at FROM clients() WHERE client_id = '${c}' LIMIT 1" 2>/dev/null \
        | python3 -c 'import sys,json
l=sys.stdin.readline()
print(json.loads(l).get("last_seen_at","") if l.strip() else "")' 2>/dev/null)"
    [[ -n "$seen" ]] || return 0
    python3 -c "import time,sys; print(int(time.time() - ${seen}/1000000))" 2>/dev/null
}

human_age() {
    local s="${1:-}"
    [[ -n "$s" ]] || { echo "unknown"; return; }
    if   (( s < 120 ));   then echo "${s}s ago"
    elif (( s < 7200 ));  then echo "$(( s / 60 )) min ago"
    elif (( s < 172800 ));then echo "$(( s / 3600 )) hours ago"
    else echo "$(( s / 86400 )) days ago"; fi
}

cmd_test() {
    local tool="" client=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --tool)   tool="${2:-}"; shift 2 ;;
            --client) client="${2:-}"; shift 2 ;;
            -h|--help) usage 0 ;;
            *) err "unknown argument: $1"; return 1 ;;
        esac
    done
    require_container || return 1
    tool="${tool:-etl2pcapng}"
    valid_token "$tool" || { err "tool name has characters that are not allowed: ${tool}"; return 1; }

    local stored
    stored="$(velo_vql "SELECT name FROM inventory() WHERE name = '${tool}' AND serve_locally AND hash" 2>/dev/null | head -1)"
    [[ -n "$stored" ]] || { err "'${tool}' is not stored on this server. Add it first:"; err "  sudo bash scripts/velo_tools.sh add ${tool} <file>"; return 1; }

    if [[ -z "$client" ]]; then
        client="$(velo_vql "SELECT client_id FROM clients() ORDER BY last_seen_at DESC LIMIT 1" 2>/dev/null \
            | python3 -c 'import sys,json
l=sys.stdin.readline()
print(json.loads(l).get("client_id","") if l.strip() else "")' 2>/dev/null)"
    fi
    [[ -n "$client" ]] || { err "no endpoint is enrolled — install a client first, then re-run"; return 1; }
    valid_token "$client" || { err "client id looks wrong: ${client}"; return 1; }

    # AN OFFLINE ENDPOINT CANNOT PROVE ANYTHING. The collection is queued until
    # the client comes back, so the flow sits in RUNNING and the test used to
    # wait two minutes and then report FAIL — measured on a box whose enrolled
    # clients came from an imported dataset and were last seen eight days ago.
    local age; age="$(client_age_seconds "$client")"
    if [[ -n "$age" ]] && (( age > VELO_ENDPOINT_MAX_AGE )); then
        log "endpoint : ${client}"
        log "SKIP — that endpoint was last seen $(human_age "$age") and is offline."
        log "  A tool test needs a live endpoint: start one, or name another with --client C.xxxx."
        log "  Nothing is wrong with '${tool}' — the server stores it and serves it on request."
        return 2
    fi

    log "endpoint : ${client}"
    log "tool     : ${tool}"

    local raw flow
    raw="$(velo_vql "SELECT collect_client(client_id='${client}', artifacts=['Generic.Utils.FetchBinary'], spec=dict(\`Generic.Utils.FetchBinary\`=dict(ToolName='${tool}'))) AS f FROM scope()" 2>&1)"
    # Take the flow id from wherever it sits in the reply, and fall back to this
    # client's newest flow if the reply carries none.
    flow="$(printf '%s' "$raw" | grep -oE 'F\.[A-Za-z0-9]{8,}' | head -1)"
    if [[ -z "$flow" ]]; then
        flow="$(velo_vql "SELECT session_id FROM flows(client_id='${client}') ORDER BY create_time DESC LIMIT 1" 2>/dev/null \
            | python3 -c 'import sys,json
l=sys.stdin.readline()
print(json.loads(l).get("session_id","") if l.strip() else "")' 2>/dev/null)"
    fi
    [[ -n "$flow" ]] || { err "could not start the collection. The server said:"; printf '%s\n' "$raw" | head -5; return 1; }
    log "flow     : ${flow}"

    local i state="" waited=0
    for i in $(seq 1 40); do
        state="$(velo_vql "SELECT state FROM flows(client_id='${client}') WHERE session_id = '${flow}'" 2>/dev/null \
            | python3 -c 'import sys,json
l=sys.stdin.readline()
print(json.loads(l).get("state","") if l.strip() else "")' 2>/dev/null)"
        [[ "$state" == "FINISHED" || "$state" == "ERROR" ]] && break
        sleep 3; waited=$((waited + 3))
    done
    log "state    : ${state:-UNKNOWN} (after ${waited}s)"

    local rows
    rows="$(velo_vql "SELECT * FROM source(client_id='${client}', flow_id='${flow}', artifact='Generic.Utils.FetchBinary')" 2>/dev/null)"
    [[ -n "$rows" ]] && { log "endpoint reported:"; printf '%s\n' "$rows" | head -3 | cut -c1-300; }

    if [[ "$state" == "FINISHED" && -n "$rows" ]]; then
        log "PASS — the endpoint downloaded '${tool}' from this appliance, no internet needed"
        return 0
    fi
    err "FAIL — state=${state:-UNKNOWN}, rows returned: $([[ -n "$rows" ]] && echo yes || echo no)"
    err "  flow log: velo_tools.sh ... or run:"
    err "  docker exec ${VELO_CONTAINER} /velociraptor/velociraptor --api_config /velociraptor/api.config.yaml query --format jsonl \"SELECT * FROM flow_logs(client_id='${client}', flow_id='${flow}')\""
    return 1
}

# ---------------------------------------------------------------------------
# status — what this server stores, and how many tools are still missing
# ---------------------------------------------------------------------------
cmd_status() {
    require_container || return 1
    log "Stored on this server (served to endpoints, no internet needed):"
    # The server can hold the SAME tool twice (two identical inventory rows —
    # seen live for VelociraptorWindowsMSI), which printed it twice and counted
    # it twice. One line per distinct tool+file; a name registered under two
    # different files still shows both, because that is a real difference.
    velo_vql "SELECT name, filename FROM inventory() WHERE serve_locally AND hash ORDER BY name" \
        | python3 -c "
import json,sys
seen=[]
for l in sys.stdin:
    if l.strip():
        d=json.loads(l); row=(d.get('name',''), d.get('filename',''))
        if row not in seen:
            seen.append(row)
for name, fn in seen:
    print(f'  {name}  <-  {fn}')
print(f'  ({len(seen)} tool(s))')"
    local missing
    missing="$(cmd_list 2>/dev/null | grep -cvE '^#|^$')"
    log "Missing (an artifact wants them, this server has not got them): ${missing:-0}"
    log "List them with: $(basename "${BASH_SOURCE[0]}") list"
}

case "${1:-}" in
    list)   shift; cmd_list "$@" ;;
    fetch)  shift; cmd_fetch "$@" ;;
    add)    shift; cmd_add "$@" ;;
    import)  shift; cmd_import "$@" ;;
    install) shift; cmd_install "$@" ;;
    status) shift; cmd_status "$@" ;;
    test)     shift; cmd_test "$@" ;;
    selftest) shift; cmd_selftest "$@" ;;
    -h|--help|help|"") usage 0 ;;
    *) err "unknown command: $1"; usage 2 ;;
esac
