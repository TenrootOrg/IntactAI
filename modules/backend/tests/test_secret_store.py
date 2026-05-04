"""Tests for services.storage.secret_store.

Covers basic CRUD + the property that secrets are isolated from
frontend_config (so export_db never dumps them into a backup).
"""

import uuid

from services.storage.secret_store import set_secret, get_secret, delete_secret


def _unique_key():
    return f"test_secret_{uuid.uuid4().hex[:12]}"


def test_set_and_get_round_trip():
    k = _unique_key()
    assert set_secret(k, "hunter2") is True
    assert get_secret(k) == "hunter2"
    delete_secret(k)


def test_set_replaces_existing_value():
    k = _unique_key()
    set_secret(k, "old")
    set_secret(k, "new")
    assert get_secret(k) == "new"
    delete_secret(k)


def test_get_missing_key_returns_none():
    assert get_secret("nonexistent_test_key_zzzzzz") is None


def test_set_with_empty_or_none_value_is_rejected():
    k = _unique_key()
    assert set_secret(k, None) is False
    assert get_secret(k) is None


def test_set_with_empty_key_is_rejected():
    assert set_secret("", "x") is False


def test_delete_is_idempotent():
    # Delete a key that doesn't exist
    assert delete_secret("nonexistent_for_delete") is True


def test_delete_then_get_returns_none():
    k = _unique_key()
    set_secret(k, "delete-me")
    assert get_secret(k) == "delete-me"
    delete_secret(k)
    assert get_secret(k) is None


def test_secrets_not_in_frontend_config_export():
    """Critical isolation: secrets must NOT appear in export_db output.

    If they did, every backup file would leak credentials.
    """
    from services.storage.export_import import export_db

    k = _unique_key()
    set_secret(k, "secret-should-not-leak")
    try:
        dump = export_db()
        # The export must not include a 'secrets' table — its absence is
        # the actual safety guarantee. (frontend_config is exported, but
        # secrets are in their own table so they're skipped.)
        flat = repr(dump)
        assert "secret-should-not-leak" not in flat, (
            "Secret value leaked into export_db() output"
        )
        assert "secrets" not in dump, (
            "export_db() includes a 'secrets' key — it must not"
        )
    finally:
        delete_secret(k)
