"""Plant evidence the detection engine is built to score, then take it away.

WHY THIS EXISTS. A pristine CI runner has nothing malicious on it, so a
collection from one produces `findings: 0` and the fusion check falls back to
asserting `relationships > 0` — which process-tree edges satisfy on any Linux
box alive. Measured: 33 entities, 7 relationships, **zero findings**. That check
passes whether correlation works or is broken, which makes it close to
worthless as a detection test.

So we give it something to find. Every item below is chosen from the mapper's
own scoring branches in services/fusion/mappers/agentic.py, and each one
deterministically crosses the severity floor:

  cron with `curl … | bash`     anomaly 60  "Suspicious cron job"
  SUID binary under /tmp        anomaly 60  "SUID binary in non-standard path"
  authorized_keys `command=`    shares the backdoor event id with
                                Linux.Detection.SSHKeyFileCmd, so the two
                                detectors of one backdoor dedup into one finding
  a uid-0 account that is not root          scored by linux.users.rootusers

None of it is malicious — a cron line that echoes, a copied `/bin/true`, a key
with no private half, an account with no password and no shell. The point is
the SHAPE, which is what the rules match on.

DELIBERATELY OPT-IN. This writes to /etc/passwd, /etc/cron.d and a home
directory. That is fine on an ephemeral runner that is destroyed minutes later
and unacceptable on anyone's real machine, so nothing happens unless a run asks
for it explicitly.
"""

import os

MARKER = "qa-e2e-probe"

CRON_PATH = f"/etc/cron.d/{MARKER}"
SUID_PATH = f"/tmp/{MARKER}-suid"
AUTHKEYS = "/root/.ssh/authorized_keys"
FAKE_USER = "qa-e2e-uid0"

# What each item is meant to produce, so a failure can say which planting did
# not come back rather than only that the count was low.
EXPECTED = {
    "cron": "Suspicious cron job",
    "suid": "SUID binary in non-standard path",
    "authorized_key": "forced-command SSH key",
    "uid0_account": "uid-0 account that is not root",
}


def plant(shell, cfg, tl=None):
    """Put the evidence in place. Returns {item: bool} — what actually landed."""
    done = {}

    # 1. cron: the command is what is scored, and `curl … | bash` is squarely in
    #    the mapper's suspicious list. It echoes rather than fetching anything.
    cron = (f"# {MARKER}\n"
            f"*/17 * * * * root curl -fsSL http://127.0.0.1:1/{MARKER} | bash\n")
    done["cron"] = _write_root(shell, cfg, CRON_PATH, cron, mode="0644", tl=tl)

    # 2. SUID in a non-standard path. A copy of /bin/true, so setting the bit
    #    grants nothing: the finding is about WHERE it is, not what it does.
    r = shell.sudo(["bash", "-c",
                    f"cp /bin/true {SUID_PATH} && chmod 4755 {SUID_PATH}"],
                   cfg.sudo_password, timeout=60, tl=tl, stage="plant")
    done["suid"] = r.ok

    # 3. authorized_keys with a forced command. A public key with no private
    #    half anywhere, so it authenticates nobody.
    key = (f'command="/bin/echo {MARKER}",no-port-forwarding '
           f'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{"Q" * 26} {MARKER}\n')
    r = shell.sudo(["bash", "-c",
                    f"mkdir -p /root/.ssh && chmod 700 /root/.ssh && "
                    f"printf '%s' {_q(key)} >> {AUTHKEYS} && chmod 600 {AUTHKEYS}"],
                   cfg.sudo_password, timeout=60, tl=tl, stage="plant")
    done["authorized_key"] = r.ok

    # 4. a second uid-0 account. No password, no shell, no home — it cannot be
    #    logged into; it exists to be *noticed*.
    r = shell.sudo(["bash", "-c",
                    f"grep -q '^{FAKE_USER}:' /etc/passwd || "
                    f"echo '{FAKE_USER}:x:0:0:{MARKER}:/nonexistent:/usr/sbin/nologin' "
                    f">> /etc/passwd"],
                   cfg.sudo_password, timeout=60, tl=tl, stage="plant")
    done["uid0_account"] = r.ok

    if tl:
        tl.event("evidence_planted", detail={k: v for k, v in done.items()})
    return done


def unplant(shell, cfg, tl=None):
    """Take it all away. Best-effort: a runner is destroyed anyway, but leaving
    a uid-0 account behind on anything else would be inexcusable."""
    shell.sudo(["bash", "-c",
                f"rm -f {CRON_PATH} {SUID_PATH}; "
                f"sed -i '/{MARKER}/d' {AUTHKEYS} 2>/dev/null; "
                f"sed -i '/^{FAKE_USER}:/d' /etc/passwd"],
               cfg.sudo_password, timeout=60, tl=tl, stage="plant")
    if tl:
        tl.event("evidence_removed", detail={"marker": MARKER})


def _write_root(shell, cfg, path, content, mode="0644", tl=None):
    r = shell.sudo(["bash", "-c",
                    f"printf '%s' {_q(content)} > {path} && chmod {mode} {path}"],
                   cfg.sudo_password, timeout=60, tl=tl, stage="plant")
    return r.ok


def _q(text):
    """Single-quote for a shell word, the safe way."""
    return "'" + text.replace("'", "'\"'\"'") + "'"
