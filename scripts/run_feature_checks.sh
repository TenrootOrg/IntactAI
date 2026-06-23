#!/usr/bin/env bash
# Run or list the feature verification commands tracked in docs/features_status.csv.
#
# This script exists because not every row in the CSV is a directly runnable
# command: some user stories require credentials, uploaded evidence, cloud
# accounts, run IDs, or destructive actions. The script provides concrete
# commands for the safe checks that are currently automated.

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CSV_PATH="$ROOT_DIR/docs/features_status.csv"
BASE_URL="${BASE_URL:-http://localhost:5001}"
BACKEND_CONTAINER="${BACKEND_CONTAINER:-intact_backend}"
RESULTS_DIR="${RESULTS_DIR:-$ROOT_DIR/test-results/feature-checks}"

usage() {
  cat <<EOF
Usage:
  bash scripts/run_feature_checks.sh --list
  bash scripts/run_feature_checks.sh --run-safe
  bash scripts/run_feature_checks.sh --run US-001
  bash scripts/run_feature_checks.sh --run US-003
  bash scripts/run_feature_checks.sh --run US-004

Environment overrides:
  BASE_URL=http://localhost:5001          Backend API base URL
  BACKEND_CONTAINER=intact_backend        Backend container name
  RESULTS_DIR=test-results/feature-checks Output folder for captured results

Notes:
  --run-safe currently runs the safe automated checks for US-001, US-003, and US-004.
  Other CSV rows are inventory entries that still need fixtures/credentials/run IDs
  before they can be turned into one-command automated checks.
EOF
}

ensure_csv() {
  if [[ ! -f "$CSV_PATH" ]]; then
    echo "ERROR: missing $CSV_PATH" >&2
    exit 1
  fi
}

list_rows() {
  ensure_csv
  python3 - <<'PY' "$CSV_PATH"
import csv
import sys
from pathlib import Path

path = Path(sys.argv[1])
with path.open(newline="") as f:
    rows = list(csv.DictReader(f))

print(f"CSV: {path}")
print(f"Rows: {len(rows)}")
print()
for row in rows:
    print(f"{row['ID']:>6} | {row['Test Status']:<12} | {row['Feature']}")
    print(f"       command: {row['Test Command / Method']}")
PY
}

validate_csv() {
  ensure_csv
  python3 - <<'PY' "$CSV_PATH"
import csv
import sys
from pathlib import Path

path = Path(sys.argv[1])
with path.open(newline="") as f:
    rows = list(csv.DictReader(f))

assert len(rows) == 24, f"expected 24 feature rows, got {len(rows)}"
assert rows, "spreadsheet is empty"
assert all(r["ID"] for r in rows), "one or more rows are missing ID"
assert all(r["User Story"] for r in rows), "one or more rows are missing User Story"
assert all(r["Expected Behavior"] for r in rows), "one or more rows are missing Expected Behavior"
assert all(r["Test Status"] for r in rows), "one or more rows are missing Test Status"
print("feature tracker CSV validation OK")
PY
}

mkdir_results() {
  mkdir -p "$RESULTS_DIR"
}

run_curl_json() {
  local name="$1"
  local path="$2"
  local outfile="$RESULTS_DIR/${name}.json"
  local code

  mkdir_results
  echo "== GET $path =="
  code="$(curl -sS -o "$outfile" -w "%{http_code}" "$BASE_URL$path" || true)"
  echo "HTTP $code saved to $outfile"

  if [[ ! "$code" =~ ^2|3 ]]; then
    echo "FAILED: $BASE_URL$path returned HTTP $code" >&2
    echo "Response preview:" >&2
    head -c 1000 "$outfile" >&2 || true
    echo >&2
    return 1
  fi
}

run_us_001() {
  validate_csv
  run_curl_json "US-001-api-health" "/api/health"
  run_curl_json "US-001-api-test" "/api/test"
}

run_us_003() {
  validate_csv
  mkdir_results
  echo "== pytest backend tests =="
  docker exec "$BACKEND_CONTAINER" python -m pytest /app/workdir/modules/backend/tests -v \
    | tee "$RESULTS_DIR/US-003-backend-pytest.txt"
}

run_us_004() {
  validate_csv
  run_curl_json "US-004-api-clients" "/api/clients"
}

run_one() {
  case "$1" in
    US-001) run_us_001 ;;
    US-003) run_us_003 ;;
    US-004) run_us_004 ;;
    *)
      echo "No automated safe runner exists yet for $1." >&2
      echo "Use --list to see the CSV command/notes, then add required fixtures or credentials." >&2
      return 2
      ;;
  esac
}

run_safe() {
  run_us_001
  run_us_003
  run_us_004
}

main() {
  case "${1:-}" in
    --help|-h) usage ;;
    --list) list_rows ;;
    --run-safe) run_safe ;;
    --run)
      if [[ -z "${2:-}" ]]; then
        echo "ERROR: --run requires a user-story ID, e.g. US-001" >&2
        usage >&2
        exit 1
      fi
      run_one "$2"
      ;;
    *)
      usage >&2
      exit 1
      ;;
  esac
}

main "$@"
