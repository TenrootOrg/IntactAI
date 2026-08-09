"""One-time migration from nginx basic-auth to the app login.

Relocated out of services/upgrade/intact.py when the upgrade engine moved to
the host. app.py runs this on EVERY boot, independent of any upgrade -- it
was only ever in that file because that is where it was written.
"""

import os
import shutil
import subprocess
from typing import Callable

from services.proc import WORKDIR, HOST_PATH, run_command

def migrate_basic_auth_to_app_login(logger: Callable = None) -> None:
    """Move a pre-auth box onto the new session login, landing the operator on
    the setup page so THEY choose the credentials.

    This function used to do the opposite, and the reasoning was wrong on a
    point of fact. It assumed the box it was upgrading had nginx Basic Auth —
    a password the operator was already typing — and argued that replacing it
    with a claimable setup page was strictly worse. Checked against the tags:

        auth_basic in intact-20260615 : 0
        auth_basic in intact-20260726 : 0
        auth_basic in development     : 3

    NO SHIPPED RELEASE EVER HAD IT. The gate was added and replaced by the app
    login inside the same unreleased window, so on every real appliance the
    recovery found nothing, fell through to a since-removed helper that
    GENERATED a random 32-character password, and stored it as the login and
    marked setup complete. The operator was locked out of their own box by a
    credential that had never existed anywhere they could have seen it. That
    is what happened on the 20260726 -> 20260803 upgrade.

    With no prior credential there is nothing to preserve, and the appliance is
    serving an unauthenticated dashboard TODAY — so the setup page is strictly
    an improvement over the status quo, not a regression from it. Hence: never
    generate a password nobody has seen. Carry one across only when the operator
    explicitly set `dashboard.password` in config.yaml, which is a real choice
    they made; otherwise write first_login: true and let them pick.

    Detection is the absence of the top-level `first_login:` key. The shipped
    config.yaml carries it, so a fresh install always has it; only a box that
    predates this feature does not. Idempotent — once the key exists this is a
    no-op, so it is safe on every upgrade, and a box already on the new scheme
    never has its credentials touched.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))

    # This module already lives under /app/services/upgrade/, so the sibling
    # import resolves without any sys.path juggling.
    try:
        from services import auth_service
    except Exception as e:
        log(f"  Could not load auth_service ({type(e).__name__}: {e}) — "
            f"skipping login migration", "warning")
        return

    flag = auth_service.read_first_login()
    if flag == auth_service.FIRST_LOGIN_ERROR:
        log("  config.yaml unreadable — skipping login migration (the login "
            "page will explain how to recover)", "warning")
        return
    if flag != auth_service.FIRST_LOGIN_ABSENT:
        # Already on the new scheme (or deliberately left in setup mode).
        return

    log("  Pre-auth install detected — moving to the new dashboard login", "info")

    # ONLY an explicitly operator-chosen password is carried across. Deleting
    # the old fallback (read a generated secret off disk, and failing that
    # GENERATE one) is the entire fix: that branch is what silently minted a
    # 32-character password nobody had ever seen and then locked the operator
    # out behind it. A password the operator did not choose and cannot know is
    # not a credential — it is a lockout with extra steps.
    user, password = _read_dashboard_credentials(log)

    if password:
        if auth_service.set_credential(user, password):
            if auth_service.write_first_login(False):
                log(f"  Dashboard login carried across (username: {user}) — the "
                    f"password you set in config.yaml under dashboard.password "
                    f"signs you in to the new login page.", "success")
                auth_service.audit('migrated_from_basic_auth',
                                   username_value=user,
                                   source="config.yaml dashboard.password")
                return
            log("  Stored the credential but could not write first_login to "
                "config.yaml — the setup page may still be served. Set "
                "first_login: false by hand.", "error")
            return
        log("  Could not store the credential from config.yaml — falling back "
            "to the setup page", "warning")

    # The normal path for every real appliance: no operator-chosen password, so
    # the operator picks their own on the setup page.
    if auth_service.write_first_login(True):
        log("  This appliance will show the SETUP page on next load, where you "
            "choose your own username and password. Complete it IMMEDIATELY — "
            "until you do, anyone who can reach the appliance can claim the "
            "account. (It has been serving an unauthenticated dashboard up to "
            "now, so this is not a new exposure, but it is your chance to end "
            "it.)", "warning")
    else:
        log("  Could not write first_login to config.yaml. Add "
            "'first_login: true' at the top level by hand to set up a login.",
            "error")

def _read_dashboard_credentials(log: Callable) -> tuple:
    """Return (username, password) from config.yaml's ``dashboard:`` block.

    Username defaults to 'admin'; password defaults to '' meaning "operator
    did not choose one — generate/keep a random secret". A malformed or
    unreadable config.yaml must never break the upgrade, so any failure
    degrades to the generated-secret path rather than raising.
    """
    config_path = os.path.join(WORKDIR, 'config.yaml')
    user, password = 'admin', ''
    try:
        import yaml  # local import — mirrors base.py's read-config idiom
        with open(config_path, 'r') as f:
            cfg = yaml.safe_load(f) or {}
        dash = cfg.get('dashboard') or {}
        if isinstance(dash, dict):
            # str() so a YAML-numeric password (e.g. `password: 123123`, which
            # safe_load hands back as an int) still hashes to what the operator
            # typed instead of blowing up on .encode().
            user = str(dash.get('id') or 'admin').strip() or 'admin'
            raw = dash.get('password')
            password = '' if raw is None else str(raw).strip()
    except FileNotFoundError:
        pass
    except Exception as e:
        log(f"  Could not read dashboard credentials from config.yaml "
            f"({type(e).__name__}: {e}) — falling back to a generated password",
            "warning")
    return user, password

def _write_nginx_htpasswd(user: str, password: str, password_path: str,
                          htpasswd_path: str, log: Callable) -> None:
    """Write the plaintext + htpasswd pair for one user/password.

    SHA-1 htpasswd format ("{SHA}<base64 sha1 digest>") — natively supported
    by nginx's auth_basic module, computed in-process so the plaintext
    password never touches a subprocess argv (see run_command's shell=True —
    a CLI arg there would be briefly visible via `ps`).

    Written with open(...,'w') (truncate in place, same inode) because docker
    bind-mounts these BY PATH — replacing the inode would leave the running
    nginx pinned to the old file and a changed password silently inert.
    """
    with open(password_path, 'w') as f:
        f.write(password)
    os.chmod(password_path, 0o600)

    import hashlib
    import base64
    digest = hashlib.sha1(password.encode()).digest()
    with open(htpasswd_path, 'w') as f:
        f.write(f"{user}:{{SHA}}{base64.b64encode(digest).decode()}\n")

    # The htpasswd file is read by the nginx WORKER process (uid/gid 101 —
    # nginx:alpine's compiled --user=nginx --group=nginx default), not the
    # root master, so owner-only 600 would make every request 500. Mirrors
    # the root:33/640 pattern already used for the IRIS web TLS key (gid 33
    # = iris-nginx's www-data).
    try:
        os.chown(htpasswd_path, 0, 101)
    except (PermissionError, OSError) as e:
        log(f"  Could not chown nginx htpasswd to root:101 ({type(e).__name__}: {e})",
            "warning")
    os.chmod(htpasswd_path, 0o640)
