"""Enforce the upgrade contract that docs/UPGRADE_CONTRACT.md describes.

Phase 1 of an upgrade runs on the OLD release's code, so a handful of conventions
are load-bearing across releases. They are cheap to break by accident and
expensive to diagnose: re-adding a backend code bind-mount "just for local
debugging" silently turns the backend legacy again, and the damage only surfaces
as a half-applied upgrade on a customer box weeks later.

These assertions are the enforcement. If one fails, read
docs/UPGRADE_CONTRACT.md before changing it — the rule is deliberate.

Run:  docker exec intact_backend python /app/workdir/tests/test_upgrade_contract.py
"""

import os
import re
import sys

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

ROOT = os.environ.get("INTACT_PATH", "/app/workdir")
BACKEND_COMPOSE = os.path.join(ROOT, "modules", "backend", "docker-compose.yaml")
CONFIG_YAML = os.path.join(ROOT, "config.yaml")

# The sentinel backend_full_mode() keys off. Kept as a literal (not imported)
# ON PURPOSE: if someone changes the constant AND the compose together, the
# detection silently flips for every release and this test must still object.
CODE_MOUNT = "./services:/app/services"


def _compose_text():
    with open(BACKEND_COMPOSE) as f:
        return f.read()


def test_backend_compose_has_no_code_bind_mounts():
    """Full-mode: the backend runs code from its image, never from the host.

    A code mount shadows the baked code, so the container keeps running whatever
    is on disk — which is exactly the state an image swap is supposed to end.
    """
    text = _compose_text()
    for mount in (CODE_MOUNT, "./routes:/app/routes",
                  "./app.py:/app/app.py", "./config.py:/app/config.py"):
        assert mount not in text, (
            f"backend compose re-introduced the code bind-mount {mount!r}. This "
            f"turns the backend legacy: backend_full_mode() returns False, Phase 1 "
            f"stops swapping the image, and upgrades silently half-apply. See "
            f"docs/UPGRADE_CONTRACT.md."
        )


def test_backend_image_tag_is_required_not_defaulted():
    """BACKEND_VERSION must have no `:-default`.

    With a default, an unstamped box boots the stale install-day image and looks
    perfectly healthy while running the wrong code.
    """
    text = _compose_text()
    m = re.search(r'image:\s*intact-backend:\$\{BACKEND_VERSION([^}]*)\}', text)
    assert m, "backend compose no longer pins image: intact-backend:${BACKEND_VERSION...}"
    spec = m.group(1)
    assert spec.startswith(":?"), (
        f"BACKEND_VERSION must be REQUIRED (':?'), got {spec!r}. A default lets a "
        f"box boot a stale image instead of failing loudly."
    )


def test_config_yaml_declares_versions_backend():
    """backend_target_tag() reads config.yaml versions.backend BEFORE VERSION.

    Without the key every box falls through to the 'development' last resort and
    hunts for an image releases do not ship.
    """
    import yaml
    with open(CONFIG_YAML) as f:
        cfg = yaml.safe_load(f) or {}
    versions = cfg.get("versions") or {}
    assert "backend" in versions, (
        "config.yaml lost versions.backend — the key the target resolves its "
        "backend image from. See docs/UPGRADE_CONTRACT.md."
    )
    assert str(versions["backend"]).strip(), "versions.backend is empty"


def test_full_mode_detection_agrees_with_the_compose():
    """The helper and the actual file must not drift apart."""
    from services.upgrade.intact import backend_full_mode
    assert backend_full_mode(BACKEND_COMPOSE) is True, (
        "backend_full_mode() says this release is legacy source-mounted. Either a "
        "code mount came back or the sentinel changed."
    )
    assert backend_full_mode("/nonexistent/docker-compose.yaml") is False, (
        "a missing compose must read as NOT full-mode (safe default)"
    )


def test_persistence_mounts_survive():
    """State must live outside the container, or a recreate destroys it."""
    text = _compose_text()
    for mount, why in (
        ("../../data:/app/data", "intact.db + upgrade_state"),
        ("../../config.yaml:/app/config.yaml", "operator config"),
        ("/var/run/docker.sock:/var/run/docker.sock", "sibling-container orchestration"),
    ):
        assert mount in text, (
            f"backend compose lost {mount!r} ({why}). Every container recreate — "
            f"which is now how upgrades work — would drop it."
        )


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as e:
                failures += 1
                print(f"FAIL {name}: {e}")
            except Exception as e:                            # pragma: no cover
                failures += 1
                print(f"ERROR {name}: {type(e).__name__}: {e}")
    print(f"\n{'FAILED' if failures else 'OK'} — {failures} failure(s)")
    sys.exit(1 if failures else 0)
