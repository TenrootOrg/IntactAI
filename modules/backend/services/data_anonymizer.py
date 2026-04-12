"""
Data Anonymizer - Masks sensitive data before LLM analysis, reverts after.

Uses pseudo-realistic values to preserve forensic context while protecting
sensitive information like IPs, usernames, emails, and paths.
"""

import re
import ipaddress
from typing import Any

# Pseudo-value pools (RFC 5737 TEST-NET-3 for external IPs)
PSEUDO_EXTERNAL_IPS = [f"203.0.113.{i}" for i in range(1, 255)]
PSEUDO_INTERNAL_IPS = [f"10.0.0.{i}" for i in range(101, 255)]
PSEUDO_USERS = [f"user{i}" for i in range(1, 100)] + [f"admin{i}" for i in range(1, 20)] + [f"svc_account{i}" for i in range(1, 20)]
PSEUDO_HOSTS = [f"HOST-{i:03d}" for i in range(1, 100)] + [f"SERVER-{i:03d}" for i in range(1, 50)] + [f"DC-{i:03d}" for i in range(1, 10)]
PSEUDO_EMAILS = [f"user{i}@example.org" for i in range(1, 100)]
PSEUDO_DOMAINS = ["YOURORG", "yourorg.local", "yourorg.internal"]
PSEUDO_CREDENTIALS = [f"SecretPass{i}!" for i in range(1, 100)] + [f"ApiKey_{i:08x}" for i in range(1, 50)] + [f"Token_{i:012x}" for i in range(1, 50)]

# Safe values that should NOT be masked
SAFE_IPS = {
    "127.0.0.1", "0.0.0.0", "::1", "localhost",
    # Public DNS
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    # Common broadcast
    "255.255.255.255"
}

SYSTEM_ACCOUNTS = {
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "NT AUTHORITY",
    "NT SERVICE", "ANONYMOUS LOGON", "Everyone", "Administrators",
    "Users", "Guests", "DnsAdmins", "Domain Admins", "Domain Users",
    "WINDOW MANAGER", "FONT DRIVER HOST", "UMFD", "DWM",
}

SAFE_PATHS = {
    r"C:\Windows",
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
}

# Field name patterns for detection (specific to avoid false positives on forensic field names)
IP_FIELD_PATTERNS = re.compile(
    r"(ip.?addr|^ip$|ip.?address|source.?ip|dest.?ip|src.?ip|dst.?ip|"
    r"remote.?addr|local.?addr|client.?ip|raddr|laddr|source.?address|dest.?address)",
    re.IGNORECASE
)

USER_FIELD_PATTERNS = re.compile(
    r"(^user$|username|user.?name|account.?name|subject.?user|target.?user|"
    r"owner|creator|domain.?name|principal.?name|display.?name)",
    re.IGNORECASE
)

HOST_FIELD_PATTERNS = re.compile(
    r"(computer|computer.?name|host.?name|^hostname$|machine.?name|"
    r"workstation|workstation.?name|server.?name|client.?machine)",
    re.IGNORECASE
)

PATH_FIELD_PATTERNS = re.compile(
    r"(path|file.?path|directory|folder|command.?line|^cmd$|^image$|"
    r"parent.?image|target.?image|source.?image|working.?dir|current.?dir)",
    re.IGNORECASE
)

EMAIL_FIELD_PATTERNS = re.compile(
    r"(email|e.?mail|mail.?address|recipient|sender)",
    re.IGNORECASE
)

CREDENTIAL_FIELD_PATTERNS = re.compile(
    r"(password|passwd|pwd|secret|credential|api.?key|bearer|"
    r"^token$|access.?token|refresh.?token|secret.?key|private.?key)",
    re.IGNORECASE
)

# Fields that contain misleading keywords but should never be masked
SAFE_FIELDS = {
    'eventid', 'eventname', 'eventrecordid', 'eventtype',
    'ruletitle', 'rulelevel', 'rulename', 'rule', 'ruleid', 'ruletitle', 'ruledescription',
    'rule_title', 'rule_id', 'rule_description',
    'severity', 'level', 'criticality', 'priority',
    'detection', 'alert', 'finding', 'match', 'hit',
    'threatname', 'categoryname', 'category', 'categoryid',
    'mitreattack', 'mitre', 'technique', 'mitre_attack',
    'tokenelevationtype', 'tokeniselevated',
    'processtokenelevationtype', 'processtokeniselevated',
    'processid', 'pid', 'parentprocessid', 'ppid',
    'logontype', 'logonid', 'subjectlogonid', 'targetlogonid', 'logonidhex',
    'authenticationlevel', 'authenticationservice',
    'authenticationpackage', 'authenticationpackagename',
    'keypath', 'registrykey', 'keylastwritetimestamp', 'keylastwritetime',
    'targetobject', 'targetfilename',
    'status', 'substatus',
    'processname', 'name', 'imagename', 'procname', 'appname',
    'displayname', 'pipename', 'rulename', 'appdomainname',
    'description', 'product', 'company', 'originalfilename',
    'falsepositives',
    'useragent',
    'accounttype', '_accounttype', 'accountdescription',
    'hostprevalence', 'hostinstanceid', 'hostid',
}

# Exact field names containing identity data (normalized: lowercase, no separators)
# Derived from all 53 Velociraptor artifact definitions across all blueprints
IDENTITY_FIELDS = {
    # Usernames -> mask as "user"
    'username': 'user',
    'user': 'user',
    '_user': 'user',
    'subjectusername': 'user',
    'targetusername': 'user',
    'attempteduser': 'user',
    'initiatinguser': 'user',
    'initiatingeffectiveuser': 'user',
    'fullname': 'user',
    'creator': 'user',
    'accountname': 'user',
    '_accountname': 'user',
    'account': 'user',
    '_account': 'user',
    # User IDs (can contain readable names in Azure/M365)
    'userid': 'user',
    'uid': 'user',
    'accountid': 'user',
    '_accountid': 'user',
    # Domains -> mask as "domain"
    'domainname': 'domain',
    'domain': 'domain',
    'subjectdomainname': 'domain',
    'targetdomainname': 'domain',
    'accountdomain': 'domain',
}


class DataAnonymizer:
    """Masks sensitive data before LLM, reverts after."""

    def __init__(self, custom_patterns: list[str] = None):
        self.mapping: dict[str, str] = {}  # original -> masked (all, including composite)
        self.reverse_mapping: dict[str, str] = {}  # masked -> original
        self._atomic_mappings: dict[str, tuple[str, str]] = {}  # original -> (masked, category) - only individual values
        self.counters = {
            "ip_ext": 0,
            "ip_int": 0,
            "email": 0,
            "user": 0,
            "host": 0,
            "domain": 0,
            "credential": 0,
        }
        self.custom_patterns = custom_patterns or []
        self.compiled_custom_patterns: list[re.Pattern] = []
        self._compile_custom_patterns()

    def _compile_custom_patterns(self):
        """Convert user patterns to compiled regex."""
        for pattern in self.custom_patterns:
            try:
                pattern = pattern.strip()
                if not pattern:
                    continue

                if pattern.startswith('/') and pattern.endswith('/'):
                    # Full regex: /pattern/
                    regex = pattern[1:-1]
                elif '*' in pattern:
                    # Wildcard: *.domain.com -> .*\.domain\.com
                    regex = pattern.replace('.', r'\.').replace('*', '.*')
                elif '|' in pattern:
                    # OR pattern: user1|user2
                    regex = f'({pattern})'
                else:
                    # Exact match
                    regex = re.escape(pattern)

                self.compiled_custom_patterns.append(
                    re.compile(regex, re.IGNORECASE)
                )
            except re.error:
                # Skip invalid patterns
                continue

    def _matches_custom_pattern(self, value: str) -> bool:
        """Check if value matches any custom pattern."""
        value_str = str(value)
        for pattern in self.compiled_custom_patterns:
            if pattern.search(value_str):
                return True
        return False

    def _classify_ip(self, ip: str) -> str:
        """Classify IP as 'internal', 'external', 'safe', or 'invalid'."""
        if ip in SAFE_IPS:
            return "safe"

        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_link_local:
                return "internal"
            if ip_obj.is_loopback:
                return "safe"
            return "external"
        except ValueError:
            return "invalid"

    def _get_or_create_pseudo(self, original: str, category: str) -> str:
        """Get existing pseudo value or create new one."""
        if original in self.mapping:
            return self.mapping[original]

        if category == "ip_ext":
            idx = self.counters["ip_ext"] % len(PSEUDO_EXTERNAL_IPS)
            pseudo = PSEUDO_EXTERNAL_IPS[idx]
            self.counters["ip_ext"] += 1
        elif category == "ip_int":
            idx = self.counters["ip_int"] % len(PSEUDO_INTERNAL_IPS)
            pseudo = PSEUDO_INTERNAL_IPS[idx]
            self.counters["ip_int"] += 1
        elif category == "user":
            idx = self.counters["user"] % len(PSEUDO_USERS)
            pseudo = PSEUDO_USERS[idx]
            self.counters["user"] += 1
        elif category == "host":
            idx = self.counters["host"] % len(PSEUDO_HOSTS)
            pseudo = PSEUDO_HOSTS[idx]
            self.counters["host"] += 1
        elif category == "email":
            idx = self.counters["email"] % len(PSEUDO_EMAILS)
            pseudo = PSEUDO_EMAILS[idx]
            self.counters["email"] += 1
        elif category == "domain":
            idx = self.counters["domain"] % len(PSEUDO_DOMAINS)
            pseudo = PSEUDO_DOMAINS[idx]
            self.counters["domain"] += 1
        elif category == "credential":
            idx = self.counters["credential"] % len(PSEUDO_CREDENTIALS)
            pseudo = PSEUDO_CREDENTIALS[idx]
            self.counters["credential"] += 1
        else:
            pseudo = "<REDACTED>"

        self.mapping[original] = pseudo
        self.reverse_mapping[pseudo] = original
        self._atomic_mappings[original] = (pseudo, category)
        return pseudo

    def _is_ip(self, value: str) -> bool:
        """Check if value looks like an IP address."""
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _is_email(self, value: str) -> bool:
        """Check if value looks like an email."""
        return bool(re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', value))

    # Full regex patterns for known credential formats (prefix + length/structure validated)
    _CREDENTIAL_PATTERNS = re.compile(
        r'^('
        r'sk-ant-[a-zA-Z0-9_-]{20,}|'              # Anthropic API key
        r'sk-[a-zA-Z0-9]{20,}|'                     # OpenAI API key
        r'ghp_[a-zA-Z0-9]{36,}|'                    # GitHub PAT (classic)
        r'gho_[a-zA-Z0-9]{36,}|'                    # GitHub OAuth
        r'ghu_[a-zA-Z0-9]{36,}|'                    # GitHub user-to-server
        r'ghs_[a-zA-Z0-9]{36,}|'                    # GitHub server-to-server
        r'github_pat_[a-zA-Z0-9_]{22,}|'            # GitHub fine-grained PAT
        r'glpat-[a-zA-Z0-9_-]{20,}|'                # GitLab PAT
        r'xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+|'        # Slack bot token
        r'xoxp-[0-9]+-[0-9]+-[a-zA-Z0-9]+|'        # Slack user token
        r'AKIA[0-9A-Z]{16}|'                        # AWS access key (AKIA + exactly 16 uppercase alphanum)
        r'AIzaSy[a-zA-Z0-9_-]{20,}'                  # Google API key (AIzaSy + 20+ chars)
        r')$'
    )

    def _is_credential(self, value: str) -> bool:
        """Check if value matches known API key, token, or hash formats."""
        if len(value) < 20:
            return False
        return bool(self._CREDENTIAL_PATTERNS.match(value))

    def _extract_domain_user(self, value: str) -> tuple[str, str] | None:
        """Extract domain and user from DOMAIN\\user format."""
        if '\\' in value:
            parts = value.split('\\', 1)
            if len(parts) == 2:
                return parts[0], parts[1]
        return None

    def _mask_ip(self, ip: str) -> str:
        """Mask an IP address based on classification."""
        ip_type = self._classify_ip(ip)
        if ip_type == "safe":
            return ip
        elif ip_type == "internal":
            return self._get_or_create_pseudo(ip, "ip_int")
        elif ip_type == "external":
            return self._get_or_create_pseudo(ip, "ip_ext")
        return ip  # invalid, leave as-is

    def _mask_user(self, user: str) -> str:
        """Mask a username, handling DOMAIN\\user format."""
        # Check if system account
        upper = user.upper()
        for sys_acct in SYSTEM_ACCOUNTS:
            if sys_acct in upper:
                return user

        # Handle DOMAIN\user format
        domain_user = self._extract_domain_user(user)
        if domain_user:
            domain, username = domain_user
            masked_domain = self._get_or_create_pseudo(domain, "domain")
            masked_user = self._get_or_create_pseudo(username, "user")
            masked = f"{masked_domain}\\{masked_user}"
            # Store full mapping for unmask
            self.mapping[user] = masked
            self.reverse_mapping[masked] = user
            return masked

        return self._get_or_create_pseudo(user, "user")

    def _mask_host(self, host: str) -> str:
        """Mask a hostname."""
        return self._get_or_create_pseudo(host, "host")

    def _mask_email(self, email: str) -> str:
        """Mask an email address."""
        return self._get_or_create_pseudo(email, "email")

    def _mask_path(self, path: str) -> str:
        """Mask user-specific parts of a path while preserving structure."""
        if not path:
            return path

        # Check if it's a safe system path
        path_upper = path.upper()
        for safe_path in SAFE_PATHS:
            if path_upper.startswith(safe_path.upper()):
                # Only mask if there's a user folder
                pass

        # Mask C:\Users\username patterns
        users_match = re.match(
            r'^(C:\\Users\\)([^\\]+)(\\.*)?$',
            path,
            re.IGNORECASE
        )
        if users_match:
            prefix, username, suffix = users_match.groups()
            masked_user = self._get_or_create_pseudo(username, "user")
            masked_path = f"{prefix}{masked_user}{suffix or ''}"
            self.mapping[path] = masked_path
            self.reverse_mapping[masked_path] = path
            return masked_path

        # Mask /home/username patterns
        home_match = re.match(
            r'^(/home/)([^/]+)(/.*)?$',
            path
        )
        if home_match:
            prefix, username, suffix = home_match.groups()
            masked_user = self._get_or_create_pseudo(username, "user")
            masked_path = f"{prefix}{masked_user}{suffix or ''}"
            self.mapping[path] = masked_path
            self.reverse_mapping[masked_path] = path
            return masked_path

        return path

    def _mask_commandline(self, cmd: str) -> str:
        """Mask sensitive data within a command line while preserving structure."""
        if not cmd:
            return cmd

        masked = cmd

        # Mask IPs in command line
        ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        for match in re.finditer(ip_pattern, cmd):
            ip = match.group(1)
            if self._is_ip(ip):
                masked_ip = self._mask_ip(ip)
                if masked_ip != ip:
                    masked = masked.replace(ip, masked_ip)

        # Mask C:\Users\username patterns
        users_pattern = r'(C:\\Users\\)([^\\"\s]+)'
        for match in re.finditer(users_pattern, cmd, re.IGNORECASE):
            full_match = match.group(0)
            username = match.group(2)
            masked_user = self._get_or_create_pseudo(username, "user")
            masked = masked.replace(full_match, f"{match.group(1)}{masked_user}")

        # Store the full command mapping if changed
        if masked != cmd:
            self.mapping[cmd] = masked
            self.reverse_mapping[masked] = cmd

        return masked

    def _mask_value(self, field_name: str, value: Any) -> Any:
        """Mask a single value based on field name and value content."""
        if value is None:
            return None

        value_str = str(value)

        # Skip empty values
        if not value_str.strip():
            return value

        # Skip boolean-like and trivial values
        if value_str.lower() in ('true', 'false', 'none', 'null', 'n/a', 'unknown', '0', '1'):
            return value

        # Skip known-safe fields (forensic metadata that contains misleading keywords)
        normalized_field = field_name.lower().replace('_', '').replace('.', '').replace(' ', '')
        if normalized_field in SAFE_FIELDS:
            return value

        # Check explicit identity fields (exact field name match from artifact definitions)
        identity_category = IDENTITY_FIELDS.get(normalized_field)
        if identity_category:
            if identity_category == 'domain':
                return self._get_or_create_pseudo(value_str, "domain")
            return self._mask_user(value_str)

        # Check custom patterns first
        if self._matches_custom_pattern(value_str):
            return self._get_or_create_pseudo(value_str, "user")

        # Detect credentials by value pattern (known API key/token/hash formats)
        if self._is_credential(value_str):
            return self._get_or_create_pseudo(value_str, "credential")

        # IP fields (value must match IP regex)
        if IP_FIELD_PATTERNS.search(field_name) and self._is_ip(value_str):
            return self._mask_ip(value_str)

        # Email fields (value must match email regex)
        if EMAIL_FIELD_PATTERNS.search(field_name) and self._is_email(value_str):
            return self._mask_email(value_str)

        # Host fields (field names are specific enough: Computer, Hostname, etc.)
        if HOST_FIELD_PATTERNS.search(field_name):
            return self._mask_host(value_str)

        # Path/Command fields - only mask embedded user profile paths
        if PATH_FIELD_PATTERNS.search(field_name):
            if "command" in field_name.lower() or "cmd" in field_name.lower():
                return self._mask_commandline(value_str)
            return self._mask_path(value_str)

        # Auto-detect by value content (for unlabeled fields)
        if self._is_ip(value_str):
            return self._mask_ip(value_str)
        if self._is_email(value_str):
            return self._mask_email(value_str)

        return value

    def mask_row(self, row: dict) -> dict:
        """Mask sensitive fields in a single row."""
        masked_row = {}
        for key, value in row.items():
            if isinstance(value, dict):
                masked_row[key] = self.mask_row(value)
            elif isinstance(value, list):
                masked_row[key] = [
                    self.mask_row(item) if isinstance(item, dict)
                    else self._mask_value(key, item)
                    for item in value
                ]
            else:
                masked_row[key] = self._mask_value(key, value)
        return masked_row

    def mask_data(self, rows: list[dict]) -> list[dict]:
        """Mask sensitive fields in artifact rows."""
        return [self.mask_row(row) for row in rows]

    def unmask_text(self, text: str) -> str:
        """Restore original values in report text."""
        if not text:
            return text

        result = text

        # Sort by length descending to replace longer strings first
        # This prevents partial replacements
        sorted_mappings = sorted(
            self.reverse_mapping.items(),
            key=lambda x: len(x[0]),
            reverse=True
        )

        for masked, original in sorted_mappings:
            result = result.replace(masked, original)

        return result

    def get_mapping_summary(self) -> dict:
        """Return summary of all mappings for debugging."""
        return {
            "total_mappings": len(self.mapping),
            "counters": self.counters,
            "sample_mappings": dict(list(self.mapping.items())[:10])
        }

    def get_masking_log_lines(self) -> list[str]:
        """Return detailed log lines showing only atomic masked values (individual IPs, users, etc.), grouped by category."""
        if not self._atomic_mappings:
            return ["[Masking] No values were masked"]

        CATEGORY_LABELS = {
            "ip_ext": "External IPs",
            "ip_int": "Internal IPs",
            "email": "Emails",
            "user": "Users",
            "host": "Hosts",
            "domain": "Domains",
            "credential": "Credentials",
        }

        # Group by category
        grouped: dict[str, list[tuple[str, str]]] = {}
        for original, (masked, category) in self._atomic_mappings.items():
            label = CATEGORY_LABELS.get(category, category)
            grouped.setdefault(label, []).append((original, masked))

        lines = ["[Masking] === Data Masking Summary ==="]
        for label, mappings in grouped.items():
            lines.append(f"[Masking] {label} ({len(mappings)}):")
            for original, masked in mappings:
                lines.append(f"[Masking]   {original} -> {masked}")

        total = len(self._atomic_mappings)
        lines.append(f"[Masking] Total: {total} values masked across {len(grouped)} categories")
        return lines
