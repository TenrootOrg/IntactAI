"""Detect whether a backend compose file runs code from the image or a bind
mount. Moved from services/upgrade/intact.py:backend_full_mode -- the packager
needs it to decide whether the backend image build even applies, and that
module no longer exists on this branch.
"""

import re

_BACKEND_CODE_MOUNT_SENTINEL = re.compile(r'\./services:/app/services')


def backend_full_mode(compose_path: str) -> bool:
    """True when the backend compose runs code from the IMAGE (no
    ./services bind mount). Missing/unreadable file -> False, the safe
    default: treat it as still source-mounted rather than assume the image
    is self-sufficient."""
    try:
        with open(compose_path, encoding='utf-8') as f:
            return not _BACKEND_CODE_MOUNT_SENTINEL.search(f.read())
    except OSError:
        return False
