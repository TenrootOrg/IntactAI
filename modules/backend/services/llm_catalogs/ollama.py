#!/usr/bin/env python3
"""Model listing for a self-hosted LLM server, queried LIVE per URL.

Every other catalog in this package mirrors a vendor's global model list into a
file under /app/data and serves it from there. This one deliberately does not,
because the question is different: not "what models exist" but "what models
does THIS server have".

  * The answer belongs to one specific host. The operator's server is usually
    another machine on the network, and two customers point at different ones —
    a single shared on-disk catalog would serve one operator another's list.
  * It changes whenever someone runs `ollama pull` on that box. A cached answer
    would hide a model that was just installed, and keep offering one that was
    removed.
  * It is cheap and local. There is no API quota to protect and no key to
    spend, which is the entire reason the other catalogs cache.

Before this, the offline model list was four hardcoded names in the settings
markup. Picking one the server did not have failed at report time, mid-case,
with a model-not-found error from Ollama.

Two shapes are supported because self-hosted servers come in both:

  ollama            GET {url}/api/tags        -> {"models": [{"name": ...}]}
  openai-compatible GET {url}/v1/models       -> {"data": [{"id": ...}]}
                    (LiteLLM proxy, vLLM, LM Studio, and Ollama's own /v1)
"""

import requests

# Short. This is a reachability probe against a server on the operator's own
# network, and it runs while they wait on the settings page — a long hang here
# reads as a frozen UI, not as a slow server.
LIST_TIMEOUT = 8


class OllamaListError(Exception):
    """Could not list models. `reason` is a stable machine token; `message` is
    operator-facing and names the URL that failed, because the usual cause is a
    typo in it or a server that is not listening."""

    def __init__(self, reason, message):
        super().__init__(message)
        self.reason = reason
        self.message = message


def _normalise(url):
    """Trim trailing slashes so f'{url}/api/tags' cannot produce a double slash
    — some proxies 404 on those."""
    return (url or '').strip().rstrip('/')


def list_models(url, kind='ollama', api_key=None, timeout=LIST_TIMEOUT):
    """Models this server reports, newest-looking first.

    Returns [{'id', 'name', 'size_bytes', 'modified'}]. Raises OllamaListError
    with an actionable reason rather than returning an empty list, so the UI can
    tell "server has no models" apart from "server unreachable" — the fixes are
    completely different (pull one vs check the URL).
    """
    base = _normalise(url)
    if not base:
        raise OllamaListError('no_url', 'No server URL set.')
    if not base.startswith(('http://', 'https://')):
        raise OllamaListError(
            'bad_url', f"'{url}' is not a URL — include http:// or https://.")

    if kind == 'ollama':
        path = '/api/tags'
    else:
        # The OpenAI SDK's base_url convention INCLUDES /v1, so that is what the
        # operator pastes and what _call_llm_offline passes through unchanged.
        # Appending '/v1/models' to it produced /v1/v1/models -> 404. Accept
        # both forms rather than making the operator guess which one this field
        # wants, since the same string is used for listing and for calling.
        path = '/models' if base.endswith('/v1') else '/v1/models'
    headers = {'Authorization': f'Bearer {api_key}'} if api_key else {}
    try:
        resp = requests.get(base + path, headers=headers, timeout=timeout)
    except requests.exceptions.ConnectTimeout:
        raise OllamaListError('timeout', f"{base} did not respond within {timeout}s.")
    except requests.exceptions.ConnectionError:
        raise OllamaListError(
            'unreachable',
            f"Could not reach {base}. Check the URL, and that the server is "
            f"reachable FROM the Intact host (not just from your workstation).")
    except requests.RequestException as e:
        raise OllamaListError('error', f"Could not reach {base}: {e}")

    if resp.status_code in (401, 403):
        raise OllamaListError(
            'auth', f"{base} rejected the request ({resp.status_code}) — it needs an API key.")
    if resp.status_code != 200:
        raise OllamaListError(
            'http_error', f"{base}{path} returned HTTP {resp.status_code}.")
    try:
        body = resp.json() or {}
    except ValueError:
        raise OllamaListError(
            'not_json',
            f"{base}{path} did not return JSON — is that a {kind} server?")

    out = []
    if kind == 'ollama':
        for m in (body.get('models') or []):
            name = m.get('name') or m.get('model')
            if not name:
                continue
            out.append({'id': name, 'name': name,
                        'size_bytes': m.get('size'),
                        'modified': m.get('modified_at')})
    else:
        for m in (body.get('data') or []):
            mid = m.get('id')
            if not mid:
                continue
            out.append({'id': mid, 'name': mid,
                        'size_bytes': None, 'modified': m.get('created')})
    return out
