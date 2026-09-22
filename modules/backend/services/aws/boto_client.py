"""Bounded boto3 clients, one honest name per AWS failure, and a preflight.

WHY THIS EXISTS.

1. TIMEOUTS. Every runner in this package built its own `boto3.client(...)`
   with library defaults: 60s connect, 60s read, and botocore's `legacy` retry
   mode (up to 5 attempts). A `light` CloudTrail sweep issues one LookupEvents
   pass per event name — 1 console + 24 IAM names, see
   cloudtrail_runner.LIGHT_EVENT_NAMES_* — per region. On an appliance with no
   route to AWS that is 25 x 5 x 60s = over two hours PER REGION of a run that
   cannot succeed, and the operator sees only "running". Nothing in the AWS
   path has a deadline (no Celery, no poller, no timeout thread), so the boto3
   socket timeouts ARE the deadline. They have to be short.

2. NAMING THE CAUSE. boto3 reports an expired key, a denied call, a region
   that does not exist and a throttle as the same `ClientError` class. Each
   runner caught `Exception`, logged the botocore repr at warning level, and
   returned []. Zero records is also what a clean account returns, so a scan
   with dead credentials completed "successfully" with nothing in it —
   the AWS version of the memory bug's "timed out" (the message named the
   symptom, not the cause).

3. PREFLIGHT. One bounded `sts:GetCallerIdentity` answers three questions at
   once, in seconds, before any collection starts: can this box reach AWS at
   all (the air-gap case), are these credentials valid, and which account are
   we in. `services/fusion/llm_sim.provider_route()` uses the same
   bounded-probe-then-say-so shape for the LLM providers.

Classification is duck-typed on the exception's class name and its
`response['Error']['Code']` rather than by catching botocore classes, so this
module imports (and is testable) with no boto3 installed.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional, Tuple

# Short on purpose — see (1) above. A LookupEvents page that has not answered
# in 20s on a healthy account is not going to; the retry gives one recovery
# from a transient blip and no more.
CONNECT_TIMEOUT = 5
READ_TIMEOUT = 20
MAX_ATTEMPTS = 2

# Error codes AWS returns for a credential that cannot be fixed by retrying.
_CREDENTIAL_CODES = {
    "InvalidClientTokenId", "UnrecognizedClientException", "InvalidAccessKeyId",
    "SignatureDoesNotMatch", "AuthFailure", "ExpiredToken", "ExpiredTokenException",
    "RequestExpired", "TokenRefreshRequired", "InvalidSecurityToken",
}
_DENIED_CODES = {
    "AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
    "AuthorizationError", "NotAuthorized", "InvalidClientTokenId.Forbidden",
}
_THROTTLE_CODES = {
    "Throttling", "ThrottlingException", "ThrottledException", "RequestThrottled",
    "RequestThrottledException", "RequestLimitExceeded", "TooManyRequestsException",
    "SlowDown",
}
# The account has not enabled this region / service in it. Not an error in the
# account's own regions, so it must not read as one.
_NOT_ENABLED_CODES = {"OptInRequired", "SubscriptionRequiredException", "UnsupportedOperation"}

# Exception CLASS names (botocore raises these without an Error code).
_NO_ROUTE_CLASSES = {
    "EndpointConnectionError", "ConnectTimeoutError", "ConnectionError",
    "ConnectionClosedError", "ReadTimeoutError", "NameResolutionError",
    "SSLError", "ProxyConnectionError", "HTTPClientError",
}
_BAD_REGION_CLASSES = {"InvalidRegionError", "NoRegionError", "EndpointResolutionError"}

# Kinds where continuing to call AWS only burns wall-clock: the next call
# fails identically. Callers stop and keep what they already collected.
FATAL_KINDS = ("credentials", "no_route", "bad_region")


class AwsFatal(Exception):
    """An AWS failure that the next call cannot recover from.

    Carries `partial` so the caller keeps the records collected BEFORE the
    failure — a run that dies on region four must not throw away regions one
    to three.
    """

    def __init__(self, kind: str, message: str, partial=None):
        super().__init__(message)
        self.kind = kind
        self.message = message
        self.partial = list(partial or [])


def _error_code(exc: BaseException) -> str:
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):
        err = resp.get("Error")
        if isinstance(err, dict):
            return str(err.get("Code") or "")
    return ""


def classify(exc: BaseException) -> Tuple[str, str]:
    """(kind, operator-readable message) for any exception a boto3 call raises.

    kind is one of: credentials, denied, no_route, bad_region, throttled,
    not_enabled, unknown.
    """
    cls = type(exc).__name__
    code = _error_code(exc)
    detail = str(exc).strip().splitlines()[0][:300] if str(exc).strip() else cls

    if code in _CREDENTIAL_CODES:
        return "credentials", (
            f"AWS rejected the credentials ({code}). They are wrong, disabled, or "
            f"the session token has expired — re-enter them in Settings > Cloud."
        )
    if code in _DENIED_CODES:
        return "denied", f"AWS denied the call ({code}): {detail}"
    if code in _THROTTLE_CODES:
        return "throttled", f"AWS throttled the call ({code}) — collection for this slice is incomplete."
    if code in _NOT_ENABLED_CODES:
        return "not_enabled", f"Service or region not enabled for this account ({code})."
    if cls in _BAD_REGION_CLASSES:
        return "bad_region", f"Not a usable AWS region ({cls}): {detail}"
    if cls in _NO_ROUTE_CLASSES:
        return "no_route", (
            f"This appliance has no route to AWS ({cls}). An AWS scan needs egress "
            f"to the AWS API endpoints; on an air-gapped install it cannot run at all. "
            f"Detail: {detail}"
        )
    return "unknown", f"{cls}: {detail}"


def client(service: str, aws_config: Dict[str, Any], region: Optional[str] = None):
    """A boto3 client with the bounded timeouts above.

    Raises whatever boto3 raises — callers classify it. Replaces the four
    identical `_safe_client` copies the runners used to carry, none of which
    passed a Config.
    """
    import boto3
    from botocore.config import Config

    kwargs: Dict[str, Any] = {
        "aws_access_key_id": aws_config["access_key_id"],
        "aws_secret_access_key": aws_config["secret_access_key"],
        "region_name": region or aws_config.get("region", "us-east-1"),
        "config": Config(
            connect_timeout=CONNECT_TIMEOUT,
            read_timeout=READ_TIMEOUT,
            retries={"max_attempts": MAX_ATTEMPTS, "mode": "standard"},
        ),
    }
    if aws_config.get("session_token"):
        kwargs["aws_session_token"] = aws_config["session_token"]
    return boto3.client(service, **kwargs)


def preflight(aws_config: Dict[str, Any], log: Optional[Callable[[str, str], None]] = None) -> Dict[str, Any]:
    """Bounded reachability + credential check. Never raises.

    Returns {'ok', 'kind', 'message', 'account', 'arn'}. `ok` False means the
    run cannot succeed and must stop NOW with `message` as the reason — that
    is the whole point: a scan that cannot work has to say why in seconds, not
    fail source by source for an hour and report "no data collected".
    """
    say = log or (lambda msg, lvl="info": None)
    out: Dict[str, Any] = {"ok": False, "kind": "", "message": "", "account": None, "arn": None}

    if not aws_config or not aws_config.get("access_key_id"):
        out["kind"] = "credentials"
        out["message"] = "No AWS credentials configured — set them in Settings > Cloud."
        return out
    try:
        sts = client("sts", aws_config)
        ident = sts.get_caller_identity()
    except ImportError as e:
        out["kind"] = "no_boto3"
        out["message"] = f"boto3 is not installed in the backend image: {e}"
        say(f"[AWS] Preflight failed: {out['message']}", "error")
        return out
    except Exception as e:  # noqa: BLE001 — classified below, never swallowed
        kind, message = classify(e)
        out["kind"], out["message"] = kind, message
        if kind == "denied":
            # AWS answered and recognised the signature — it only refused this
            # call. sts:GetCallerIdentity is normally undeniable by IAM policy
            # but an SCP can block it, and that must not stop a scan whose
            # actual collection permissions are fine. Reachability and
            # credential validity are both proven by getting this far.
            out["ok"] = True
            say(f"[AWS] Preflight: AWS reachable, credentials valid, but "
                f"GetCallerIdentity was denied ({message}) — continuing.", "warning")
            return out
        say(f"[AWS] Preflight failed ({kind}): {message}", "error")
        return out

    out["ok"] = True
    out["account"] = ident.get("Account")
    out["arn"] = ident.get("Arn")
    say(f"[AWS] Preflight OK — account {out['account']} as {out['arn']}", "info")
    return out
