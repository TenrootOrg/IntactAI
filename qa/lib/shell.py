"""Running commands on the appliance, including as root.

The sudo password is fed on STDIN via `sudo -S`, never as `sudo -p` and never
anywhere in argv. On this box /proc is readable by other local users, so a
password in a command line is visible to anyone with a shell for as long as the
process lives — and install.sh runs for the better part of an hour.

Long-running commands stream to a log file AND to the console rather than being
captured and printed at the end. install.sh takes up to 90 minutes; a harness
that shows nothing until it finishes is indistinguishable from a hung one, and
if it is killed the captured output is lost precisely when it was needed.
"""

import os
import subprocess
import threading


class CommandResult:
    def __init__(self, argv, rc, out, log_path=None):
        self.argv, self.rc, self.out, self.log_path = argv, rc, out, log_path

    @property
    def ok(self):
        return self.rc == 0

    def __repr__(self):
        return f"<CommandResult rc={self.rc} {' '.join(self.argv[:3])}…>"


def run(argv, timeout=300, cwd=None, env=None, check=False, input_text=None):
    """Plain command, output captured. For quick probes."""
    proc = subprocess.run(
        argv, capture_output=True, text=True, timeout=timeout, cwd=cwd,
        env={**os.environ, **(env or {})} if env else None,
        input=input_text)
    out = (proc.stdout or "") + (proc.stderr or "")
    res = CommandResult(argv, proc.returncode, out)
    if check and not res.ok:
        raise RuntimeError(f"{' '.join(argv)} failed rc={proc.returncode}: {out[-500:]}")
    return res


def sudo(argv, password, timeout=300, cwd=None, log_path=None, tl=None,
         env=None, stage=None):
    """Run argv as root.

    `sudo -S -k -p ''` reads the password from stdin. -k forces a prompt even
    if a sudo timestamp is cached, so behaviour does not silently depend on
    whether the operator ran sudo five minutes ago — a run that works on a warm
    box and fails on a cold one is the worst kind of flake.
    """
    full = ["sudo", "-S", "-k", "-p", ""] + list(argv)
    return stream(full, timeout=timeout, cwd=cwd, log_path=log_path, tl=tl,
                  env=env, stdin_text=password + "\n", stage=stage,
                  argv_for_log=["sudo", "…"] + list(argv))


def stream(argv, timeout=7200, cwd=None, log_path=None, tl=None, env=None,
           stdin_text=None, stage=None, argv_for_log=None, echo=True):
    """Run a command, streaming stdout+stderr to a log file and the console.

    Returns a CommandResult whose `.out` is the full captured text — redaction
    happens at write time via the timeline's redactor if one is supplied, so
    nothing unredacted is ever written to disk.
    """
    display = argv_for_log or argv
    if tl:
        tl.event("cmd_begin", stage=stage,
                 detail={"argv": " ".join(display)[:300], "log": log_path})

    redact = getattr(tl, "redact", None) or (lambda s: s)

    fh = open(log_path, "a", encoding="utf-8") if log_path else None
    if fh:
        fh.write(f"\n$ {' '.join(display)}\n")
        fh.flush()

    proc = subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE if stdin_text is not None else None,
        text=True, bufsize=1, cwd=cwd,
        env={**os.environ, **(env or {})} if env else None)

    if stdin_text is not None:
        try:
            proc.stdin.write(stdin_text)
            proc.stdin.flush()
            proc.stdin.close()
        except BrokenPipeError:
            pass          # command exited before reading stdin

    chunks = []

    def pump():
        for line in proc.stdout:
            line = redact(line)
            chunks.append(line)
            if fh:
                fh.write(line)
                fh.flush()
            if echo:
                print("    | " + line.rstrip()[:200], flush=True)

    t = threading.Thread(target=pump, daemon=True)
    t.start()

    try:
        rc = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        rc = -9
        if tl:
            tl.fail("cmd_timeout", stage=stage,
                    detail={"argv": " ".join(display)[:200], "timeout_s": timeout})
    t.join(timeout=10)
    if fh:
        fh.close()

    out = "".join(chunks)
    if tl:
        tl.event("cmd_end", status="ok" if rc == 0 else "fail", stage=stage,
                 detail={"rc": rc, "lines": len(chunks)})
    return CommandResult(display, rc, out, log_path)


def docker(args, timeout=120):
    return run(["docker"] + list(args), timeout=timeout)


def container_names():
    r = docker(["ps", "-a", "--format", "{{.Names}}"])
    return [n for n in r.out.splitlines() if n.strip()]


def container_state(name):
    r = docker(["inspect", "-f", "{{.State.Status}}|{{.State.Health.Status}}", name])
    if not r.ok:
        return None, None
    status, _, health = r.out.strip().partition("|")
    return status or None, (health if health not in ("", "<no value>") else None)
