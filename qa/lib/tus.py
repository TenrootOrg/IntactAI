"""A minimal tus client — the only door into the flow-free ingest paths.

`/api/uploads/` is not a Flask route. nginx rewrites it to `/files/` and proxies
to tusd, so the backend only ever sees the webhook tusd fires afterwards. That
webhook is what starts the real work: `purpose=timesketch` runs the same
`process_kape_upload` the Velociraptor pipeline uses, and `purpose=velociraptor`
imports a collector result AND fuses it into the case.

Why this matters for testing: `/api/timesketch/import` demands a `flow_id` that
exists in an in-memory registry, and the only two routes that write to that
registry both dispatch `Windows.Triage.Targets`. So the flow-driven path cannot
be reached without a Windows endpoint. The tus upload has no such coupling — it
takes a ZIP and runs the pipeline. It is the entire reason a Linux-only run can
exercise Timesketch at all.

Two constraints inherited from the deployment, both non-obvious:

  * It goes through nginx on 443, which applies `auth_request /api/auth/verify`.
    A session cookie is required, so this must use the authenticated client the
    auth phase built — the loopback bypass is not available here.
  * `purpose=timesketch` requires the filename to end in `.zip`, checked in the
    pre-create hook before a single byte is uploaded.

Only the slice of the protocol the appliance needs is implemented: create, then
sequential PATCH. No resumption, no concurrent parts, no deferred length --
tusd's defaults handle the rest and a QA upload has nothing to resume.
"""

import base64
import os

# tusd streams to disk, so the ceiling is time and memory in the proxy, not the
# chunk size. 8 MiB keeps a 500 MB collector to ~60 requests while staying well
# under any intermediary's buffer.
CHUNK_BYTES = 8 * 2**20

TUS_VERSION = "1.0.0"


def encode_metadata(pairs):
    """tus Upload-Metadata: comma-separated `key base64(value)`.

    A key with an empty value is legal and meaningful here — `plaso_parser=""`
    is how a caller says "use every parser", which is exactly what a Linux
    ingest wants and what the hook's `win7` default would otherwise override.
    """
    out = []
    for key, value in pairs.items():
        if value is None:
            continue
        raw = value if isinstance(value, bytes) else str(value).encode("utf-8")
        out.append(f"{key} {base64.b64encode(raw).decode('ascii')}")
    return ",".join(out)


def upload(client, path, metadata, chunk_bytes=CHUNK_BYTES, tl=None,
           stage=None):
    """Upload `path` through tus. Returns the upload id, or None.

    `client` is a qa.lib.api.Client carrying the session cookie; its `.s` is a
    requests session and `.base` the https origin.
    """
    size = os.path.getsize(path)
    meta = dict(metadata)
    meta.setdefault("filename", os.path.basename(path))

    headers = {
        "Tus-Resumable": TUS_VERSION,
        "Upload-Length": str(size),
        "Upload-Metadata": encode_metadata(meta),
    }
    if tl:
        tl.event("tus_create", stage=stage,
                 detail={"file": os.path.basename(path), "bytes": size,
                         "purpose": meta.get("purpose")})

    r = client.s.post(client.base + "/api/uploads/", headers=headers, timeout=120)
    if r.status_code not in (200, 201):
        if tl:
            tl.event("tus_create", status="fail", stage=stage,
                     detail={"status": r.status_code, "body": r.text[:200]})
        return None

    # tusd answers with an absolute or root-relative Location; the upload id is
    # its last path segment either way.
    location = r.headers.get("Location") or ""
    upload_id = location.rstrip("/").rsplit("/", 1)[-1]
    if not upload_id:
        return None

    offset = 0
    with open(path, "rb") as fh:
        while offset < size:
            chunk = fh.read(chunk_bytes)
            if not chunk:
                break
            pr = client.s.patch(
                f"{client.base}/api/uploads/{upload_id}",
                data=chunk,
                headers={"Tus-Resumable": TUS_VERSION,
                         "Upload-Offset": str(offset),
                         "Content-Type": "application/offset+octet-stream"},
                timeout=600)
            if pr.status_code not in (200, 204):
                if tl:
                    tl.event("tus_patch", status="fail", stage=stage,
                             detail={"status": pr.status_code,
                                     "offset": offset,
                                     "body": pr.text[:200]})
                return None
            # Trust the server's offset over our own arithmetic: it is the
            # authority on what it actually stored.
            offset = int(pr.headers.get("Upload-Offset", offset + len(chunk)))

    if tl:
        tl.event("tus_done", status="ok" if offset >= size else "fail",
                 stage=stage, detail={"upload_id": upload_id, "bytes": offset})
    return upload_id if offset >= size else None
