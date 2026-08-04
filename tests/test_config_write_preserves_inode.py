"""config.yaml migrations must not swap the file's inode.

config.yaml is bind-mounted into the backend container AS A FILE:

    modules/backend/docker-compose.yaml:40
        ../../config.yaml:/app/config.yaml:ro

Docker binds by inode. A write that replaces the file (os.replace, os.rename,
write-to-temp-then-rename) leaves the running container reading the OLD file
for the rest of its life. The migration writes correctly to disk, the host sees
the new content, and the platform never does.

That is the worst failure shape available: everything reports success. A
config migration during an upgrade would silently have no effect, and nobody
would know to look.

Run: python3 tests/test_config_write_preserves_inode.py
"""

import os
import re
import sys
import tempfile

REPO = os.environ.get("INTACT_PATH") or os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))
MIGRATIONS = os.path.join(REPO, "modules", "backend", "services", "upgrade",
                          "config_migrations.py")


def _source():
    with open(MIGRATIONS, encoding="utf-8") as fh:
        return fh.read()


def _strip_comments(src):
    """The fix documents the bug and names os.replace in its own docstring, so
    a raw search would match the explanation rather than the code."""
    src = re.sub(r'""".*?"""', "", src, flags=re.S)
    return "\n".join(l for l in src.splitlines()
                     if not l.lstrip().startswith("#"))


def test_no_rename_based_write():
    code = _strip_comments(_source())
    for bad in ("os.replace(", "os.rename(", "shutil.move("):
        assert bad not in code, \
            f"{bad} is back in config_migrations.py — it swaps the inode and " \
            f"the backend container will keep reading the old config.yaml"


def test_the_write_is_a_truncate_in_place():
    code = _strip_comments(_source())
    assert re.search(r"open\(\s*path\s*,\s*['\"]w['\"]", code), \
        "config.yaml is no longer written by truncating the real path in place"


def test_it_still_fsyncs():
    """Preserving the inode costs the rename's atomicity, so durability of the
    temp copy is what makes a crash recoverable. Losing the fsync would leave
    neither a good file nor a good temp."""
    code = _strip_comments(_source())
    assert code.count("os.fsync(") >= 2, \
        "expected an fsync on both the temp copy and the real file"


# --- behaviour ------------------------------------------------------------


def test_inode_and_mode_survive_a_write():
    try:
        sys.path.insert(0, os.path.join(REPO, "modules", "backend"))
        from services.upgrade.config_migrations import _write_lines
    except Exception as exc:                                  # noqa: BLE001
        print(f"  (skipped: backend deps unavailable — {exc})")
        return

    d = tempfile.mkdtemp()
    path = os.path.join(d, "config.yaml")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("schema_version: 1\ndomain: old\n")
    os.chmod(path, 0o600)

    before = os.stat(path).st_ino
    _write_lines(path, ["schema_version: 2", "domain: new"], lambda *a, **k: None)
    after = os.stat(path).st_ino

    assert before == after, \
        f"inode changed {before} -> {after}; the bind-mounted container would " \
        f"still be reading the old file"
    assert os.stat(path).st_mode & 0o777 == 0o600, "file mode was not preserved"
    with open(path, encoding="utf-8") as fh:
        assert "domain: new" in fh.read(), "new content was not written"
    leftovers = [f for f in os.listdir(d) if f.startswith(".config")]
    assert not leftovers, f"temp file left behind on success: {leftovers}"


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
