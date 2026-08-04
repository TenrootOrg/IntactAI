"""The auth gate has to be wired in everywhere, or it protects nothing.

test_auth_service.py covers the policy in isolation. This covers the wiring
around it — the places where a correct auth_service can still leave the appliance
open, locked, or silently missing its audit trail:

  * app.py must actually install the before_request gate and set a persisted
    secret key. A gate nobody calls is decoration.
  * nginx.conf must no longer carry auth_basic (or the operator gets two
    prompts), and must gate the two paths the backend cannot see:
    /velociraptor/ and /api/uploads/ proxy to non-Flask upstreams.
  * The auth_request subrequest must not forward the request body. Without
    `proxy_pass_request_body off` nginx buffers each tus PATCH to satisfy the
    subrequest, defeating the `proxy_request_buffering off` that /api/uploads/
    sets on purpose for large uploads.
  * /api/uploads/ must return a real 401 on auth failure, NOT a redirect. tus
    runs over XMLHttpRequest, which follows 3xx transparently, so a 302 would
    hand the tus client the login page's HTML with status 200 and it would treat
    that as a successful chunk.
  * The htpasswd bind mount must be gone from nginx's compose file at the same
    time as its generator, or docker creates a DIRECTORY at the missing source
    path and nginx fails to start.
  * The support bundle must copy the audit log explicitly — its log discovery
    only scans /var/log inside containers and would never find
    /app/data/auth/audit.jsonl — and must register it in the composition
    breakdown, or the bundle silently reports no auth history.
  * The frontend 401 handler must live on the global window.fetch hook in
    active-case.js, not in api-client.js. There are ~116 raw fetch() call sites
    against 3 that use the api helper, so hooking the helper would leave almost
    every panel rendering blank on an expired session instead of redirecting.

Static assertions over the source files — no browser, no live app, no stack.

Run: docker exec intact_backend python3 /app/workdir/tests/test_auth_wiring.py
"""

import os
import re
import sys

REPO = os.environ.get("INTACT_PATH", "/app/workdir")

APP = os.path.join(REPO, "modules", "backend", "app.py")
NGINX_CONF = os.path.join(REPO, "modules", "nginx", "config", "nginx.conf")
NGINX_COMPOSE = os.path.join(REPO, "modules", "nginx", "docker-compose.yaml")
BUNDLE = os.path.join(REPO, "modules", "backend", "services", "support_bundle.py")
ACTIVE_CASE = os.path.join(REPO, "modules", "nginx", "html", "js", "active-case.js")
UPLOAD_JS = os.path.join(REPO, "modules", "nginx", "html", "js", "upload.js")
LOGIN_HTML = os.path.join(REPO, "modules", "nginx", "html", "login.html")
SETUP_HTML = os.path.join(REPO, "modules", "nginx", "html", "setup.html")
MODULES_SH = os.path.join(REPO, "lib", "modules.sh")
UPGRADE = os.path.join(REPO, "modules", "backend", "services", "upgrade", "intact.py")
AUTH_ROUTES = os.path.join(REPO, "modules", "backend", "routes", "auth_routes.py")


def _read(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _strip_comments_hash(text):
    """Drop `#` comment lines — so a directive only 'present' inside an
    explanatory comment doesn't count as wired up."""
    return "\n".join(ln for ln in text.splitlines()
                     if not ln.lstrip().startswith("#"))


def _strip_js_comments(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return "\n".join(ln for ln in text.splitlines()
                     if not ln.lstrip().startswith("//"))


# --- app.py: the gate is actually installed ---------------------------------


def test_the_before_request_gate_is_registered():
    src = _read(APP)
    assert "@app.before_request" in src, \
        "no before_request hook — nothing enforces authentication on /api/"
    assert "gate_decision" in src, \
        "the hook does not consult auth_service.gate_decision()"


def test_the_gate_returns_401_with_a_reason():
    src = _read(APP)
    gate = src[src.index("@app.before_request"):]
    gate = gate[:gate.index("\n# ", 10)] if "\n# " in gate[10:] else gate
    assert "401" in gate, "the gate does not reject unauthenticated requests"
    assert "'reason'" in gate or '"reason"' in gate, (
        "the 401 carries no reason, so login.html cannot distinguish an expired "
        "session from a missing one")


def test_the_session_key_is_persisted_not_random_per_boot():
    src = _read(APP)
    assert "session_secret_key()" in src, (
        "app.secret_key is not sourced from auth_service.session_secret_key(); "
        "a key regenerated per boot logs everyone out on every backend restart")
    assert "os.urandom" not in src.split("secret_key")[0][-200:], \
        "the secret key looks like it is generated inline per process"


def test_the_session_cookie_is_hardened():
    src = _strip_comments_hash(_read(APP))
    for setting in ("SESSION_COOKIE_HTTPONLY=True",
                    "SESSION_COOKIE_SECURE=True",
                    "SESSION_COOKIE_SAMESITE='Lax'"):
        assert setting in src.replace(" ", "").replace(
            "SESSION_COOKIE_SAMESITE='Lax'", "SESSION_COOKIE_SAMESITE='Lax'") \
            or setting.replace(" ", "") in src.replace(" ", ""), \
            f"missing cookie hardening: {setting}"


def test_the_auth_blueprint_is_registered():
    src = _read(APP)
    assert "register_blueprint(auth_bp)" in src, "auth_bp is never registered"


# --- nginx: basic auth gone, auth_request in place --------------------------


def test_basic_auth_is_gone():
    """Leaving it would mean two prompts for one login."""
    conf = _strip_comments_hash(_read(NGINX_CONF))
    assert "auth_basic" not in conf, (
        "nginx still carries an auth_basic directive — the operator would be "
        "prompted twice, and the htpasswd it needs is no longer generated")
    assert "auth_basic_user_file" not in conf


def test_the_htpasswd_mount_is_gone():
    """A bind mount whose source no longer exists makes docker create a
    DIRECTORY there, and nginx then fails to start."""
    compose = _strip_comments_hash(_read(NGINX_COMPOSE))
    assert ".htpasswd" not in compose, \
        "nginx still bind-mounts an htpasswd file that is no longer generated"


def test_the_generator_is_gone_from_the_install_path():
    src = _strip_comments_hash(_read(MODULES_SH))
    assert "generate_nginx_secrets" not in src, \
        "install still calls generate_nginx_secrets, which no longer exists"


def test_the_two_non_flask_paths_are_gated():
    conf = _read(NGINX_CONF)

    def block(marker):
        start = conf.index(marker)
        return conf[start:conf.index("\n        location ", start + 10)]

    for marker in ("location /velociraptor/ {", "location /api/uploads/ {"):
        body = _strip_comments_hash(block(marker))
        assert "auth_request /api/auth/verify;" in body, (
            f"{marker} is not gated — it proxies to a non-Flask upstream, so "
            f"the backend's before_request hook can never see it")


def test_the_subrequest_does_not_forward_the_body():
    conf = _read(NGINX_CONF)
    start = conf.index("location = /api/auth/verify")
    body = _strip_comments_hash(conf[start:conf.index("}", start)])
    assert "internal;" in body, \
        "the auth subrequest location is not `internal` — it is externally callable"
    assert "proxy_pass_request_body off;" in body, (
        "the subrequest forwards the request body; nginx would buffer every tus "
        "PATCH to satisfy it, defeating proxy_request_buffering off")
    assert 'proxy_set_header Content-Length "";' in body


def test_the_upload_path_401s_instead_of_redirecting():
    """tus runs over XHR, which follows redirects transparently — a 302 would be
    read as a successful PATCH carrying the login page's HTML."""
    conf = _read(NGINX_CONF)
    start = conf.index("location /api/uploads/ {")
    body = _strip_comments_hash(conf[start:conf.index("\n        location ", start + 10)])
    assert "error_page 401 = @upload_unauthorized;" in body, \
        "the upload path does not route its 401 to the JSON handler"
    assert "@login_redirect" not in body, \
        "the upload path redirects on 401 — XHR would follow it and see HTTP 200"

    handler_start = conf.index("location @upload_unauthorized")
    handler = conf[handler_start:conf.index("}", handler_start)]
    assert "return 401" in handler, "the upload 401 handler does not return 401"
    assert "302" not in handler


def test_the_navigable_path_does_redirect():
    """/velociraptor/ is opened in a browser address bar, so a redirect to the
    login page is right there — the alternative is nginx's raw 401 page."""
    conf = _read(NGINX_CONF)
    start = conf.index("location /velociraptor/ {")
    body = _strip_comments_hash(conf[start:conf.index("\n        location ", start + 10)])
    assert "error_page 401 = @login_redirect;" in body

    handler_start = conf.index("location @login_redirect")
    handler = conf[handler_start:conf.index("}", handler_start)]
    assert "return 302 /login.html" in handler


def test_the_static_dashboard_is_deliberately_not_gated():
    """It must stay reachable so login.html can be served at all; it holds no
    case data, and the frontend redirects on its first 401."""
    conf = _read(NGINX_CONF)
    start = conf.rindex("location / {")
    body = _strip_comments_hash(conf[start:conf.index("}", start)])
    assert "auth_request" not in body, (
        "the static root is gated, which would make the login page itself "
        "unreachable")


# --- the login/setup pages exist and are self-contained ---------------------


def test_both_pages_exist_and_are_standalone():
    for path in (LOGIN_HTML, SETUP_HTML):
        html = _read(path)
        assert "/api/auth/status" in html, f"{path} never checks auth status"
        # Must not pull in the dashboard bundle: these pages have to render for
        # an unauthenticated visitor, whose every /api call 401s. Check for real
        # script tags rather than the word "Alpine", which appears in the
        # explanatory comments.
        bundled = re.findall(r'<script[^>]+src=["\']([^"\']+)', html)
        assert not bundled, \
            f"{os.path.basename(path)} loads external scripts {bundled}; it must be self-contained"


def test_the_login_page_states_the_recovery_path_unconditionally():
    """The operator explicitly asked for the reset instructions to be visible
    up front, not only once already locked out."""
    html = _read(LOGIN_HTML)
    assert "first_login" in html, \
        "the login page never mentions the first_login recovery switch"
    assert "config.yaml" in html
    # It must not be hidden behind the lockout element.
    lock_index = html.index('id="lockbox"')
    hint_index = html.rindex("first_login")
    assert hint_index > lock_index, "recovery hint appears only inside the lockout box"


def test_the_login_page_explains_expiry_and_credential_change():
    html = _read(LOGIN_HTML)
    assert "expired" in html, "no message for an expired session"
    assert "credentials_changed" in html, \
        "no message for 'the password was changed', so those users see a bare form"


def test_the_setup_page_warns_it_is_claimable():
    html = _read(SETUP_HTML).lower()
    assert "anyone" in html and "network" in html, \
        "the setup page does not warn that an unclaimed appliance is up for grabs"


# --- frontend: the 401 interceptor is on the hook that sees every call ------


def test_the_401_handler_is_on_the_global_fetch_hook():
    src = _read(ACTIVE_CASE)
    assert "window.fetch = function" in src, "the global fetch hook is gone"
    assert "resp.status === 401" in src, (
        "active-case.js does not intercept 401. This is the only place every "
        "/api call passes through — there are ~116 raw fetch() sites against 3 "
        "using the api helper, so hooking anywhere else covers almost nothing")
    assert "/login.html" in src, "the 401 handler never navigates to the login page"


def test_the_401_redirect_is_debounced():
    """8 setInterval pollers means one expiry produces a burst of 401s."""
    src = _strip_js_comments(_read(ACTIVE_CASE))
    assert "_redirecting" in src, \
        "no latch on the 401 redirect — concurrent 401s would race each other"


def test_the_bootstrap_fetches_also_check_401():
    """listCases/createCase/deleteCase use the pristine fetch and so skip the
    hook. ensureActiveCase() runs on every page load, so without a check an
    expired session sits on a blank dashboard."""
    src = _read(ACTIVE_CASE)
    assert "_guard401" in src, \
        "the raw _fetch call sites do not check for 401"
    assert src.count("_guard401(r)") >= 3, \
        "not every raw _fetch call site checks 401"


def test_tus_handles_401_itself():
    """tus is XHR-based and never passes through the fetch hook."""
    src = _read(UPLOAD_JS)
    assert "401" in src, "upload.js ignores auth failures"
    assert "/login.html" in src, "upload.js never redirects to the login page"
    stripped = _strip_js_comments(src)
    assert "return false" in stripped, (
        "onShouldRetry never returns false, so an expired session makes tus "
        "retry a 401 until its budget runs out and report a network error")


# --- support bundle ---------------------------------------------------------


def test_the_bundle_copies_the_audit_log():
    src = _read(BUNDLE)
    assert "_copy_auth_audit_log" in src, (
        "the support bundle never copies the auth audit log; its log discovery "
        "only scans /var/log inside containers and would never find it")
    assert "AUDIT_LOG" in src, "the bundle does not reference the audit log path"


def test_the_audit_log_is_in_the_composition_breakdown():
    """Two hardcoded loops drive bundle_composition_bytes. Missing from them, the
    log is in the zip but the manifest reports nothing."""
    src = _read(BUNDLE)
    # Anchor on the composition dict specifically — support_bundle.py has an
    # earlier `for sub in (...)` that just makedirs the staging subdirs, and
    # matching that one would make this test pass while the manifest stays wrong.
    composition_at = src.index("composition: Dict")
    match = re.search(r"for sub in \(([^)]*)\):", src[composition_at:])
    assert match, "could not find the composition subdir loop"
    assert "'auth'" in match.group(1), (
        "'auth' is not in the composition loop, so bundle_composition_bytes "
        "silently omits the audit log")


def test_the_bundle_includes_rotated_generations():
    src = _read(BUNDLE)
    assert "AUDIT_KEEP" in src, (
        "only the current log is collected; a brute-force burst that triggered "
        "rotation would have its evidence left behind")


# --- upgrade migration ------------------------------------------------------


def test_the_upgrade_migrates_instead_of_opening_setup():
    src = _read(UPGRADE)
    assert "migrate_basic_auth_to_app_login" in src, \
        "no migration path for boxes upgrading from Basic Auth"
    start = src.index("def migrate_basic_auth_to_app_login")
    body = src[start:src.index("\ndef ", start + 10)]
    assert "set_credential" in body, \
        "the migration does not carry the existing password over"
    assert "write_first_login(False)" in body, \
        "the migration never closes setup mode"


def test_the_migration_is_called_by_both_upgrade_flows():
    src = _strip_comments_hash(_read(UPGRADE))
    calls = src.count("migrate_basic_auth_to_app_login(logger=log)")
    assert calls >= 2, (
        f"the migration runs in only {calls} upgrade flow(s); both the online "
        f"and offline paths need it or one of them locks the operator out")


def test_the_migration_only_opens_setup_as_a_last_resort():
    src = _read(UPGRADE)
    start = src.index("def migrate_basic_auth_to_app_login")
    body = src[start:src.index("\ndef ", start + 10)]
    true_at = body.index("write_first_login(True)")
    false_at = body.index("write_first_login(False)")
    assert false_at < true_at, (
        "setup mode is opened before the credential migration is attempted — "
        "that publishes a claimable setup page on every upgrade")


def test_the_migration_is_a_noop_once_the_flag_exists():
    """Otherwise every subsequent upgrade would re-migrate (or worse, reset)."""
    src = _read(UPGRADE)
    start = src.index("def migrate_basic_auth_to_app_login")
    body = src[start:src.index("\ndef ", start + 10)]
    assert "FIRST_LOGIN_ABSENT" in body, \
        "the migration does not gate on the flag being absent"


# --- routes -----------------------------------------------------------------


def test_setup_closes_the_flag_before_storing_the_credential():
    """Reverse order means a failed config write leaves the setup page served
    WITH a credential set — permanently claimable."""
    src = _read(AUTH_ROUTES)
    start = src.index("def auth_setup")
    body = src[start:src.index("\n@auth_bp", start)]
    write_at = body.index("write_first_login(False)")
    store_at = body.index("set_credential(")
    assert write_at < store_at, (
        "the credential is stored before setup is closed; a config-write "
        "failure would then leave the appliance permanently claimable")


def test_setup_is_refused_once_the_appliance_is_claimed():
    src = _read(AUTH_ROUTES)
    start = src.index("def auth_setup")
    body = src[start:src.index("\n@auth_bp", start)]
    assert "MODE_SETUP" in body and "403" in body, \
        "the setup endpoint does not refuse requests once setup is complete"


def test_verify_does_no_database_work():
    """It runs once per tus PATCH — ~2000 times for a 10 GB upload."""
    src = _read(AUTH_ROUTES)
    start = src.index("def auth_verify")
    body = src[start:]
    for forbidden in ("get_secret", "set_secret", "credential_generation()",
                      "has_credential"):
        assert forbidden not in body, (
            f"/api/auth/verify calls {forbidden} — that is a database hit on a "
            f"path nginx fires once per upload chunk")


def test_changing_the_password_requires_the_current_one():
    src = _read(AUTH_ROUTES)
    start = src.index("def auth_change_password")
    body = src[start:src.index("\n@auth_bp", start)]
    assert "verify_password" in body, (
        "the password can be changed with only a session cookie, so a stolen "
        "cookie could lock the real operator out")


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
