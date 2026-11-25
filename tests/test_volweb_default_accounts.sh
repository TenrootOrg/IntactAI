#!/usr/bin/env bash
# VolWeb's entrypoint (initadmin) seeds admin/password (superuser) and
# user/password into an empty database. seed_volweb_admin() added Intact's own
# admin but left both upstream accounts able to log in on every box. This runs
# the seeder's real Python against a fake Django user table and pins:
#   1. admin and user end up inactive with no usable password (locked, not deleted);
#   2. Intact's own admin stays an active superuser with the stored password;
#   3. a box whose configured VolWeb id IS "admin" keeps that account working.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; TOTAL=0
ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  ok   - $1"; }
fail() { TOTAL=$((TOTAL+1)); echo "  FAIL - $1"; }

LOG_FILE="$(mktemp)"
SCRIPT_DIR="$ROOT"
FAKE="$(mktemp -d)"
trap 'rm -rf "$LOG_FILE" "$FAKE"' EXIT

source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/modules/volweb.sh"

# A minimal django.contrib.auth: the users initadmin leaves behind, then the
# state after the seeder's script is dumped to $STATE.
mkdir -p "$FAKE/django/contrib/auth"
touch "$FAKE/django/__init__.py" "$FAKE/django/contrib/__init__.py"
cat > "$FAKE/django/contrib/auth/__init__.py" <<'PY'
import atexit, json, os
class _U:
    def __init__(self, username, superuser=False, password='password'):
        self.username, self.is_superuser, self.is_staff = username, superuser, superuser
        self.is_active, self.password = True, password
    def set_password(self, p): self.password = p
    def set_unusable_password(self): self.password = None
    def save(self): pass
_DB = {n: _U(n, s) for n, s in (('admin', True), ('user', False))}
class _Q(list):
    def exclude(self, username): return _Q(u for u in self if u.username != username)
class _M:
    def get_or_create(self, username, defaults):
        created = username not in _DB
        if created: _DB[username] = _U(username, password=None)
        return _DB[username], created
    def filter(self, username__in): return _Q(_DB[n] for n in username__in if n in _DB)
class _Model: objects = _M()
def get_user_model(): return _Model
atexit.register(lambda: json.dump({n: [u.is_active, u.password, u.is_superuser] for n, u in _DB.items()},
                                  open(os.environ['STATE'], 'w')))
PY

docker() { [[ "$1" == exec ]] && PYTHONPATH="$FAKE" python3 -I -c 'import sys; sys.path.insert(0, sys.argv[1]); exec(sys.stdin.read())' "$FAKE"; }
get_volweb_admin_password() { echo 'S3cret-!$"x'; }
log_info() { :; }

state() { python3 -c "import json,sys; d=json.load(open('$STATE')); print(d.get(sys.argv[1]))" "$1"; }

echo "seed_volweb_admin locks VolWeb's built-in accounts:"
export STATE="$FAKE/state1.json"
read_config() { echo "tenroot"; }
seed_volweb_admin >/dev/null || fail "seeder exited non-zero"
[[ "$(state admin)" == "[False, None, True]" ]] && ok "admin is inactive with no usable password" || fail "admin still usable: $(state admin)"
[[ "$(state user)" == "[False, None, False]" ]] && ok "user is inactive with no usable password" || fail "user still usable: $(state user)"
[[ "$(state tenroot)" == "[True, 'S3cret-!\$\"x', True]" ]] && ok "Intact's admin is an active superuser with the stored password" || fail "tenroot wrong: $(state tenroot)"

export STATE="$FAKE/state2.json"
read_config() { echo "admin"; }
seed_volweb_admin >/dev/null || fail "seeder exited non-zero"
[[ "$(state admin)" == "[True, 'S3cret-!\$\"x', True]" ]] && ok "a configured id of 'admin' is kept active" || fail "configured admin locked: $(state admin)"
[[ "$(state user)" == "[False, None, False]" ]] && ok "user is still locked when the id is 'admin'" || fail "user still usable: $(state user)"

echo "test_volweb_default_accounts.sh: ${TOTAL} run, $((TOTAL-PASS)) failed"
[[ $PASS -eq $TOTAL ]]
