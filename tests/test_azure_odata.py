"""Tests for the Azure OData $filter builder (services/azure/collectors.build_odata_filter).

Pure string builder for Graph API queries: time window + optional user/IP filters
(OR across multiples). All deterministic.

Run:  docker exec intact_backend python /app/workdir/tests/test_azure_odata.py
"""

import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.azure.collectors import build_odata_filter as B   # noqa: E402


def test_time_only():
    assert B("createdDateTime", "2026-01-01") == "createdDateTime ge 2026-01-01"


def test_time_window():
    out = B("ts", "S", end_date="E")
    assert out == "ts ge S and ts le E"


def test_single_user():
    out = B("ts", "S", user_field="userPrincipalName", target_users=["a@x"])
    assert out == "ts ge S and userPrincipalName eq 'a@x'"


def test_multiple_users_or_grouped():
    out = B("ts", "S", user_field="u", target_users=["a", "b"])
    assert out == "ts ge S and (u eq 'a' or u eq 'b')"


def test_single_ip():
    out = B("ts", "S", ip_field="ipAddress", target_ips=["1.2.3.4"])
    assert out == "ts ge S and ipAddress eq '1.2.3.4'"


def test_multiple_ips_or_grouped():
    out = B("ts", "S", ip_field="ip", target_ips=["1.1.1.1", "2.2.2.2"])
    assert "ip eq '1.1.1.1' or ip eq '2.2.2.2'" in out and out.startswith("ts ge S and (")


def test_user_filter_needs_both_field_and_users():
    # users without a field -> ignored; field without users -> ignored
    assert B("ts", "S", target_users=["a"]) == "ts ge S"
    assert B("ts", "S", user_field="u") == "ts ge S"


def test_combined_time_user_ip():
    out = B("ts", "S", end_date="E", user_field="u", target_users=["a"],
            ip_field="ip", target_ips=["9.9.9.9"])
    assert out == "ts ge S and ts le E and u eq 'a' and ip eq '9.9.9.9'"


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1; print(f"FAIL {fn.__name__}"); traceback.print_exc()
    print(f"\n{len(fns)-failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
