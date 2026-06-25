"""Regression tests for services/data_anonymizer.py.

Covers the seven masking bugs reported from production agentic runs:
SIDs labelled as users, GUIDs labelled as users, emails labelled as
users, NetBIOS workstation names labelled as domains, AzureAD /
NT VIRTUAL MACHINE / "-" leaking into the domain pool, and IPs being
swapped for other IPs instead of indexed labels.

Plus invariants: SID passthrough, safe-IP passthrough, cross-artifact
consistency (same value -> same label), round-trip unmask.

Run with:
    docker exec intact_backend python -m pytest \\
        /app/services/agentic/tests/test_data_anonymizer.py -v
"""

from services.data_anonymizer import DataAnonymizer


# ---------------------------------------------------------------------------
# Bug 1: Windows SIDs were labelled as users — now pass through unchanged.
# ---------------------------------------------------------------------------

def test_well_known_sid_passes_through():
    a = DataAnonymizer()
    assert a._mask_value("SubjectUserName", "S-1-5-18") == "S-1-5-18"


def test_per_user_sid_passes_through():
    a = DataAnonymizer()
    full = "S-1-5-21-1685316442-2140859937-1953833132-1000"
    assert a._mask_value("TargetUserName", full) == full


# ---------------------------------------------------------------------------
# Bug 2: GUIDs labelled as users — now go to dedicated GUID pool.
# ---------------------------------------------------------------------------

def test_guid_in_userid_field_gets_guid_label():
    a = DataAnonymizer()
    assert a._mask_value("userid", "23B41BBD-409A-4077-9483-4C935E0A0C59") == "GUID1"


# ---------------------------------------------------------------------------
# Bug 3: IPs swapped for other IPs — now indexed labels.
# ---------------------------------------------------------------------------

def test_internal_ip_gets_internal_label():
    a = DataAnonymizer()
    assert a._mask_value("ip_address", "10.5.4.3") == "InternalIP1"
    assert a._mask_value("source_ip", "192.168.1.50") == "InternalIP2"


def test_external_ip_gets_external_label():
    a = DataAnonymizer()
    assert a._mask_value("dest_ip", "93.184.216.34") == "ExternalIP1"


def test_safe_ips_pass_through():
    a = DataAnonymizer()
    for safe in ["8.8.8.8", "1.1.1.1", "127.0.0.1"]:
        assert a._mask_value("ip_address", safe) == safe


# ---------------------------------------------------------------------------
# Bug 4: Workstation names like DESKTOP-566AT85 in *DomainName fields were
# labelled as a domain — now route to the host pool.
# ---------------------------------------------------------------------------

def test_workstation_name_in_domain_field_routes_to_host():
    a = DataAnonymizer()
    assert a._mask_value("SubjectDomainName", "DESKTOP-566AT85") == "Hostname1"


def test_real_dns_domain_passes_through():
    """Per user decision, real DNS domains preserve LLM context."""
    a = DataAnonymizer()
    assert a._mask_value("SubjectDomainName", "ACME.COM") == "ACME.COM"
    assert a._mask_value("SubjectDomainName", "corp.local") == "corp.local"


# ---------------------------------------------------------------------------
# Bug 5b: Domains in *DomainName fields were getting Domain1/2/3 labels
# which destroyed context (the LLM couldn't tell that the user downloaded
# from canva.com vs internal.corp.example). Per user decision, ALL real
# domains now pass through to preserve full context. The two domain-side
# behaviours that remain:
#   - Workstation names in *DomainName (DESKTOP-...) reroute to host pool
#   - Bare IPs in *DomainName reroute to IP masking
# ---------------------------------------------------------------------------

def test_public_domain_passes_through():
    a = DataAnonymizer()
    assert a._mask_value("DomainName", "canva.com") == "canva.com"
    assert a._mask_value("DomainName", "anydesk.com") == "anydesk.com"
    assert a._mask_value("DomainName", "7-zip.org") == "7-zip.org"


def test_public_domain_subdomain_passes_through():
    a = DataAnonymizer()
    assert a._mask_value("DomainName", "www.canva.com") == "www.canva.com"
    assert a._mask_value("DomainName", "drive.google.com") == "drive.google.com"
    assert a._mask_value("DomainName", "raw.githubusercontent.com") == "raw.githubusercontent.com"


def test_org_domain_passes_through_too():
    """Per user decision, all real domains pass through for LLM context."""
    a = DataAnonymizer()
    assert a._mask_value("DomainName", "tenroot.io") == "tenroot.io"
    assert a._mask_value("DomainName", "internal.corp.example") == "internal.corp.example"


def test_ip_in_domain_field_routes_to_ip_pool():
    """Some Windows logs put a bare IP in DomainName — mask as IP, not pass through."""
    a = DataAnonymizer()
    assert a._mask_value("DomainName", "10.0.0.5") == "InternalIP1"


# ---------------------------------------------------------------------------
# Bug 5: Service / system identifiers leaked into the domain pool — now
# always passed through regardless of which field they appear in.
# ---------------------------------------------------------------------------

def test_azuread_passes_through_in_domain_field():
    a = DataAnonymizer()
    assert a._mask_value("SubjectDomainName", "AzureAD") == "AzureAD"


def test_nt_virtual_machine_passes_through_in_domain_field():
    a = DataAnonymizer()
    assert a._mask_value("AccountDomain", "NT VIRTUAL MACHINE") == "NT VIRTUAL MACHINE"


def test_microsoftaccount_passes_through_in_domain_field():
    a = DataAnonymizer()
    assert a._mask_value("TargetDomainName", "MicrosoftAccount") == "MicrosoftAccount"


# ---------------------------------------------------------------------------
# Bug 6: Bare dashes / underscores in placeholder fields were getting
# masked — now skipped.
# ---------------------------------------------------------------------------

def test_dash_value_is_skipped():
    a = DataAnonymizer()
    assert a._mask_value("SubjectDomainName", "-") == "-"


def test_underscore_value_is_skipped():
    a = DataAnonymizer()
    assert a._mask_value("UserName", "_") == "_"


def test_n_a_passes_through():
    a = DataAnonymizer()
    assert a._mask_value("UserName", "n/a") == "n/a"


# ---------------------------------------------------------------------------
# Bug 7: Emails landing in user-typed fields got user-pool labels — now
# always routed to the email pool.
# ---------------------------------------------------------------------------

def test_email_in_user_field_routes_to_email_pool():
    a = DataAnonymizer()
    assert a._mask_value("UserName", "nofl@tenroot.io") == "Email1"


# ---------------------------------------------------------------------------
# Happy paths still work after the restructure.
# ---------------------------------------------------------------------------

def test_real_username_uses_indexed_label():
    a = DataAnonymizer()
    assert a._mask_value("SubjectUserName", "NofLevi") == "Username1"


def test_real_hostname_uses_indexed_label():
    a = DataAnonymizer()
    assert a._mask_value("Computer", "NofLaptop") == "Hostname1"


# ---------------------------------------------------------------------------
# Cross-artifact consistency: same value across multiple events / fields
# must map to the same label, every time.
# ---------------------------------------------------------------------------

def test_same_username_keeps_same_label_across_fields():
    a = DataAnonymizer()
    assert a._mask_value("SubjectUserName", "NofLevi") == "Username1"
    # Different field, same value
    assert a._mask_value("AccountName", "NofLevi") == "Username1"
    # Inside a row dict, still same label
    row = a.mask_row({"username": "NofLevi", "ip_address": "10.5.4.3"})
    assert row["username"] == "Username1"
    assert row["ip_address"] == "InternalIP1"


def test_same_ip_keeps_same_label_across_fields():
    a = DataAnonymizer()
    assert a._mask_value("source_ip", "10.5.4.3") == "InternalIP1"
    assert a._mask_value("dest_ip", "10.5.4.3") == "InternalIP1"


# ---------------------------------------------------------------------------
# Round-trip: mask -> unmask returns the originals in narrative text.
# ---------------------------------------------------------------------------

def test_unmask_restores_originals():
    a = DataAnonymizer()
    a._mask_value("SubjectUserName", "NofLevi")
    a._mask_value("ip_address", "10.5.4.3")
    text = "Username1 logged in from InternalIP1"
    assert a.unmask_text(text) == "NofLevi logged in from 10.5.4.3"


def test_unmask_handles_label_substring_collision():
    """Username1 vs Username10 — unmask must replace the longer first."""
    a = DataAnonymizer()
    # Force ten distinct usernames so we have Username1 .. Username10
    for i in range(1, 11):
        a._mask_value("UserName", f"user{i}")
    # The 10th original is "user10", masked as "Username10"
    text = "User Username10 acted, then Username1 acted"
    assert a.unmask_text(text) == "User user10 acted, then user1 acted"
