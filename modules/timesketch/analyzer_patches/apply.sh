#!/bin/bash
# Patch two upstream Timesketch analyzer bugs, inside the vendor image.
#
# Runs INSIDE the Timesketch container from the `command:` prologue in
# modules/timesketch/docker-compose.yaml, exactly like llm_providers/apply.sh.
#
# CONTRACT: this script MUST NOT be able to stop Timesketch from starting.
# No `set -e`, no `set -u`, no pipefail; every path reaches `exit 0`. A
# missed patch means one analyzer keeps failing, which is an inconvenience;
# a container that will not start is an outage.
#
# Why a start-up prologue and not `docker cp`: /opt/venv is image-layer
# content with no volume on it, so anything copied in is destroyed by the next
# `compose up`/recreate. A prologue re-applies on every up, force-recreate and
# restart — which covers install.sh, both upgrade paths, and the
# Settings->Timesketch restart, with no code in any of them.
#
# BOTH patches are upstream bugs, diagnosed on real data (2026-08-27), not
# guesses:
#
#  1. win_evtxgap.py:258  `event_count.append(df_append, sort=False)`
#     DataFrame.append() was REMOVED in pandas 2.0 and this image ships
#     pandas 2.x. The line is only reached when missing_days is non-empty —
#     i.e. exactly when the analyzer has found an event-log gap, which is the
#     only time anyone cares. So evtx_gap fails 100% of the time it has
#     something to report. Replaced with pd.concat, the documented successor.
#
#  2. regex_features.py:263  `",".join(attribute_field)`
#     Raises `TypeError: sequence item 4: expected str instance, NoneType
#     found` whenever a plaso EVTX record's `strings` array contains a null —
#     which real Microsoft-Windows-Bits-Client records do. This is why
#     feature_extraction fails on some timelines and not others, and why the
#     failure looked random. Coerces to str and drops Nones.
#
# Idempotent: each patch checks for its own marker first.

SRC_LOG="${INTACT_TS_PATCH_LOG:-/var/log/timesketch/intact_analyzer_patches.log}"

log() { printf '%s intact-analyzer-patches: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$SRC_LOG" 2>/dev/null; }

mkdir -p "$(dirname "$SRC_LOG")" 2>/dev/null

# Locate the installed analyzers package without hardcoding a Python version —
# the image is on 3.14 today and has moved before.
PKG="$(python3 - <<'PY' 2>/dev/null
try:
    import os, timesketch.lib.analyzers as a
    print(os.path.dirname(a.__file__))
except Exception:
    pass
PY
)"

if [ -z "$PKG" ] || [ ! -d "$PKG" ]; then
    log "analyzers package not found — nothing patched"
    exit 0
fi
log "analyzers package: $PKG"

# ---- patch 1: evtx_gap / pandas 2 --------------------------------------
GAP="$PKG/win_evtxgap.py"
if [ -f "$GAP" ]; then
    if grep -q "INTACT-PATCH pandas2-concat" "$GAP" 2>/dev/null; then
        log "win_evtxgap already patched"
    elif grep -q "event_count = event_count.append(df_append, sort=False)" "$GAP" 2>/dev/null; then
        python3 - "$GAP" <<'PY' 2>>"$SRC_LOG"
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
old = "            event_count = event_count.append(df_append, sort=False)"
new = ("            # INTACT-PATCH pandas2-concat: DataFrame.append() was removed\n"
       "            # in pandas 2.0; this line is only reached when a gap WAS\n"
       "            # found, so the analyzer failed exactly when it had something\n"
       "            # to report.\n"
       "            event_count = pd.concat([event_count, df_append], sort=False,\n"
       "                                    ignore_index=True)")
if old in s:
    open(p, "w", encoding="utf-8").write(s.replace(old, new, 1))
    print("patched win_evtxgap")
PY
        grep -q "INTACT-PATCH pandas2-concat" "$GAP" 2>/dev/null \
            && log "win_evtxgap patched (pandas2 concat)" \
            || log "win_evtxgap patch DID NOT APPLY"
    else
        log "win_evtxgap: expected line absent (upstream changed?) — skipped"
    fi
fi

# ---- patch 2: regex_features / None in strings[] ------------------------
RF="$PKG/feature_extraction_plugins/regex_features.py"
if [ -f "$RF" ]; then
    if grep -q "INTACT-PATCH join-skip-none" "$RF" 2>/dev/null; then
        log "regex_features already patched"
    elif grep -q 'attribute_value = ",".join(attribute_field)' "$RF" 2>/dev/null; then
        python3 - "$RF" <<'PY' 2>>"$SRC_LOG"
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
old = '                attribute_value = ",".join(attribute_field)'
new = ('                # INTACT-PATCH join-skip-none: a plaso EVTX record\'s\n'
       '                # strings[] can contain nulls (real\n'
       '                # Microsoft-Windows-Bits-Client records do), and a bare\n'
       '                # join raises TypeError on them — which is why this\n'
       '                # analyzer failed on some timelines and not others.\n'
       '                attribute_value = ",".join(\n'
       '                    str(_x) for _x in attribute_field if _x is not None)')
if old in s:
    open(p, "w", encoding="utf-8").write(s.replace(old, new, 1))
    print("patched regex_features")
PY
        grep -q "INTACT-PATCH join-skip-none" "$RF" 2>/dev/null \
            && log "regex_features patched (skip None in strings[])" \
            || log "regex_features patch DID NOT APPLY"
    else
        log "regex_features: expected line absent (upstream changed?) — skipped"
    fi
fi

# ---- patch 3: utils._fix_np_nan / numpy on a non-scalar --------------
#  utils.py:257  `if numpy.isnan(value)`
#  numpy.isnan() over a LIST or array returns an array, and `if <array>` raises
#  "The truth value of an empty array is ambiguous". The guard below it only
#  catches TypeError, so the ValueError escapes and kills browser_timeframe
#  outright. Only a scalar can be NaN in the sense this helper means.
UT="$PKG/utils.py"
if [ -f "$UT" ]; then
    if grep -q "INTACT-PATCH isnan-scalar-only" "$UT" 2>/dev/null; then
        log "utils._fix_np_nan already patched"
    elif grep -q "if numpy.isnan(value):" "$UT" 2>/dev/null; then
        python3 - "$UT" <<'PYEOF' 2>>"$SRC_LOG"
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
old = "        if numpy.isnan(value):"
new = ("        # INTACT-PATCH isnan-scalar-only: numpy.isnan() over a list or\n"
       "        # array returns an ARRAY, and `if <array>` raises ValueError\n"
       "        # which the except TypeError below does not catch -- it killed\n"
       "        # browser_timeframe outright. Only a scalar can be NaN here.\n"
       "        if numpy.isscalar(value) and numpy.isnan(value):")
if old in s:
    open(p, "w", encoding="utf-8").write(s.replace(old, new, 1))
    print("patched utils._fix_np_nan")
PYEOF
        if grep -q "INTACT-PATCH isnan-scalar-only" "$UT" 2>/dev/null; then
            log "utils._fix_np_nan patched (scalar-only isnan)"
        else
            log "utils._fix_np_nan patch DID NOT APPLY"
        fi
    else
        log "utils._fix_np_nan: expected line absent (upstream changed?) -- skipped"
    fi
fi

# ---- patch 4: the ROOT CAUSE -- upload path drops timeline_id ----------
#  tasks.py:470  build_sketch_analysis_pipeline(sketch_id, searchindex.id,
#                                               user_id=None)
#  build_index_pipeline ALREADY receives timeline_id (its own signature, line
#  398) and simply does not pass it on, so it defaults to None. Its sibling
#  caller, api/v1/resources/timeline.py:206, passes it correctly.
#
#  Everything scheduled through an UPLOAD therefore ran with timeline_id=None,
#  which caused two failures that look unrelated:
#    * AnalyzerOutput.platform_meta_data["timeline_id"] is None -> the
#      analyzer's own jsonschema rejects its output ("None is not of type
#      'integer'"), so it reports ERROR after tagging its events perfectly
#      well. Measured: account_finder, domain, browser_timeframe.
#    * saved aggregations get "timeline_ids": [null] -> every visualization
#      the analyzers create fails to open with
#      RequestError(400, 'No value specified for terms query').
#
#  Fixing it HERE fixes both, for every caller -- our pipeline and anything an
#  analyst uploads through the Timesketch GUI -- rather than only for the
#  imports this appliance happens to drive.
TK="$PKG/../tasks.py"
if [ -f "$TK" ]; then
    if grep -q "INTACT-PATCH pass-timeline-id" "$TK" 2>/dev/null; then
        log "tasks.build_index_pipeline already patched"
    elif grep -q "sketch_id, searchindex.id, user_id=None" "$TK" 2>/dev/null; then
        python3 - "$TK" <<'PYEOF' 2>>"$SRC_LOG"
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
old = "            sketch_id, searchindex.id, user_id=None\n"
new = ("            # INTACT-PATCH pass-timeline-id: build_index_pipeline already\n"
       "            # takes timeline_id and dropped it here, so every analyzer\n"
       "            # scheduled by an upload ran with timeline_id=None -- failing\n"
       "            # its own output schema and writing unopenable visualizations\n"
       "            # (timeline_ids: [null]).\n"
       "            sketch_id, searchindex.id, user_id=None, timeline_id=timeline_id\n")
if old in s:
    open(p, "w", encoding="utf-8").write(s.replace(old, new, 1))
    print("patched tasks.build_index_pipeline")
PYEOF
        if grep -q "INTACT-PATCH pass-timeline-id" "$TK" 2>/dev/null; then
            log "tasks.build_index_pipeline patched (pass timeline_id)"
        else
            log "tasks.build_index_pipeline patch DID NOT APPLY"
        fi
    else
        log "tasks.build_index_pipeline: expected line absent (upstream changed?) -- skipped"
    fi
fi

exit 0
