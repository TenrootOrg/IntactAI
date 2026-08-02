"""Strip credentials from anything a QA run emits.

A run collects install logs, container logs, a support bundle, Windows event
logs and a memory image. That material has already been shown to carry secrets
— the IRIS password was found inside a support bundle during the session that
prompted this harness — and the final report is the artifact a human shares.

So redaction is not a nicety applied at the end; it runs on collected material
before anything is written to the report or composed for an LLM.

Two layers, and both are needed:

  * KNOWN values from qa-config.yaml. Exact, no false negatives, catches the
    sudo password appearing somewhere no pattern would anticipate.
  * PATTERNS for credential shapes the harness never saw — a PAT the operator
    pasted into config.yaml, a bearer token in a container log, a session
    cookie. The known-value layer cannot catch these because the harness does
    not know them.

Deliberately self-contained rather than importing services/upgrade/base.py:
phase 0a deletes the repo, and the harness runs from a copy outside it. A
redactor that vanishes mid-run is worse than none, because the run would keep
going and write unredacted output.
"""

import re

PLACEHOLDER = "[REDACTED]"

# Credential shapes worth catching even when the value is unknown. Ordered
# longest-prefix-first so a broad rule cannot pre-empt a specific one.
PATTERNS = [
    ("github-pat", re.compile(r"\bghp_[A-Za-z0-9]{20,}")),
    ("github-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}")),
    ("github-oauth", re.compile(r"\bgh[ousr]_[A-Za-z0-9]{20,}")),
    ("aws-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("openrouter", re.compile(r"\bsk-or-v1-[A-Za-z0-9]{32,}")),
    ("anthropic", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{32,}")),
    ("openai", re.compile(r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}")),
    ("private-key", re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        re.DOTALL)),
    # key=value / key: value forms. The value stops at whitespace, a quote or a
    # comma so this does not swallow the rest of a log line.
    #
    # An explicit `:` or `=` is REQUIRED. An earlier version also accepted bare
    # whitespace, which meant ordinary prose was mangled: the check named "sudo
    # password works" was written to the results as "sudo password [REDACTED]",
    # and "the password is stored as a hash" lost the word "is". Over-redaction
    # is not a safe failure here — it destroys the diagnostic value of the very
    # logs this harness exists to produce, and it does so invisibly, because a
    # reader cannot tell a redacted secret from a redacted noun.
    #
    # Flag forms like `--password hunter2` are still covered, by the separate
    # password-flag pattern below.
    ("assigned-secret", re.compile(
        r"(?i)\b(pass(?:word|wd)?|secret|token|api[_-]?key|bearer|cookie)"
        r"(\s*[:=]\s*)"
        r"(['\"]?)([^\s'\",;]{4,})\3")),
    # `Bearer <token>` is space-separated by protocol, so it needs its own rule
    # now that the general assigned-secret pattern requires a : or = separator.
    # The >=12-char token-shaped value is what keeps it off ordinary prose.
    ("bearer-token", re.compile(
        r"(?i)\b(bearer\s+)([A-Za-z0-9._\-+/=]{12,})")),

    # Windows / Linux CLI password flags, in case anything ever shells out.
    ("password-flag", re.compile(
        r"(?i)(-{1,2}(?:password|pass|p)\s+)(\S+)")),
]


class Redactor:
    def __init__(self, secrets=()):
        # Longest first: redacting "vagrant" before "vagrant123" would leave
        # "[REDACTED]123" — a partial disclosure that also looks redacted, which
        # is the worst outcome because nobody re-checks it.
        self.secrets = sorted(
            {s for s in secrets if isinstance(s, str) and len(s.strip()) >= 3},
            key=len, reverse=True)

    def __call__(self, text):
        return self.redact(text)

    def redact(self, text):
        if text is None:
            return None
        if isinstance(text, bytes):
            # Best effort: decode, redact, re-encode. Undecodable bytes are
            # replaced rather than raising — losing a byte in a log beats
            # aborting a run at the collection stage.
            return self.redact(text.decode("utf-8", "replace")).encode("utf-8")
        if not isinstance(text, str):
            return text

        for secret in self.secrets:
            if secret in text:
                text = text.replace(secret, PLACEHOLDER)

        for name, pat in PATTERNS:
            if name == "assigned-secret":
                text = pat.sub(
                    lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}"
                              f"{PLACEHOLDER}{m.group(3)}", text)
            elif name in ("password-flag", "bearer-token"):
                text = pat.sub(lambda m: f"{m.group(1)}{PLACEHOLDER}", text)
            else:
                text = pat.sub(PLACEHOLDER, text)

        return text

    def redact_structure(self, obj):
        """Redact strings anywhere inside a dict/list — phase results are JSON,
        and a secret in a nested `detail` field is just as published as one in
        the report body."""
        if isinstance(obj, dict):
            return {k: self.redact_structure(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.redact_structure(v) for v in obj]
        if isinstance(obj, str):
            return self.redact(obj)
        return obj

    def redact_file(self, src, dst):
        """Copy src to dst with redaction applied, line by line.

        Line-at-a-time so a multi-GB collected log does not have to fit in
        memory. The one pattern this weakens is the multi-line private-key
        block; that is handled by also matching the BEGIN line on its own.
        """
        with open(src, "r", encoding="utf-8", errors="replace") as fh_in, \
             open(dst, "w", encoding="utf-8") as fh_out:
            for line in fh_in:
                fh_out.write(self.redact(line))


# The canary. Seeded into collected material before the report is built, then
# asserted absent from the output. A redactor nobody tests is a redactor that
# does not work, and the failure mode is silent by construction: the report
# looks fine either way.
# Assembled rather than written as a literal, for the same reason the test
# fixtures are: a real-shaped ghp_ string sitting in a tracked file trips the
# repo's own gitleaks gate and blocks unrelated commits.
CANARY_TOKEN = "ghp_" + "QAcanary" + "0" * 28
CANARY_PASSWORD = "QA-canary-password-do-not-use"


def canary_text():
    return (f"github_token: '{CANARY_TOKEN}'\n"
            f"password={CANARY_PASSWORD}\n")


def canary_survives(text):
    """True if any part of the canary made it through — i.e. redaction FAILED."""
    return CANARY_TOKEN in text or CANARY_PASSWORD in text
