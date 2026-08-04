"""SSH to the Windows target — bootstrap and teardown only.

Scope is deliberately narrow. SSH installs the Velociraptor client at the start
and removes it at the end. Everything in between — the malicious activity, the
KAPE collection, the memory acquisition — runs THROUGH Velociraptor, because a
QA that side-channelled around the product would prove the tools work while
proving nothing about the platform.

paramiko rather than `sshpass -p`, and this is not a style preference. A
password in argv on the Windows side lands in the process-creation event log
(4688 / Sysmon 1) that this QA then collects via KAPE, ingests into Timesketch,
fuses into the Case, and packages into the support bundle and the final report
— carrying the credential through the entire pipeline the harness exists to
test. paramiko puts it in the SSH auth exchange and nowhere else.
"""

import posixpath
import re
import stat as statmod

try:
    import paramiko
except ImportError:                      # pragma: no cover
    paramiko = None


class WindowsTarget:
    def __init__(self, host, username, password, port=22, tl=None, timeout=30):
        if paramiko is None:
            raise RuntimeError(
                "paramiko is not installed. Install it with:\n"
                "    sudo apt-get install -y python3-paramiko\n"
                "sshpass is NOT an acceptable substitute here — it puts the "
                "password in argv, where it lands in the Windows event log "
                "this QA collects.")
        self.host, self.username, self.password = host, username, password
        self.port, self.tl, self.timeout = port, tl, timeout
        self._client = None

    # --- connection ------------------------------------------------------

    def connect(self):
        if self._client:
            return self._client
        c = paramiko.SSHClient()
        # The target is a throwaway lab VM with a host key that changes every
        # rebuild. AutoAdd rather than pinning because a QA that fails on a
        # rebuilt VM tests the operator's patience, not the product.
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(hostname=self.host, port=self.port, username=self.username,
                  password=self.password, timeout=self.timeout,
                  allow_agent=False, look_for_keys=False)
        self._client = c
        if self.tl:
            self.tl.ok("win_connected", detail={"host": self.host})
        return c

    def close(self):
        if self._client:
            try:
                self._client.close()
            finally:
                self._client = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()

    # --- execution -------------------------------------------------------

    def run(self, command, timeout=300, shell="cmd"):
        """Run a command. Returns (rc, stdout+stderr).

        Default shell is cmd because OpenSSH for Windows starts cmd.exe; a
        PowerShell payload goes through run_powershell, which encodes it so
        quoting cannot mangle it in transit.
        """
        c = self.connect()
        chan = c.get_transport().open_session()
        chan.settimeout(timeout)
        chan.exec_command(command)

        out = []
        while True:
            if chan.recv_ready():
                out.append(chan.recv(65536).decode("utf-8", "replace"))
            elif chan.recv_stderr_ready():
                out.append(chan.recv_stderr(65536).decode("utf-8", "replace"))
            elif chan.exit_status_ready():
                break
        while chan.recv_ready():
            out.append(chan.recv(65536).decode("utf-8", "replace"))
        while chan.recv_stderr_ready():
            out.append(chan.recv_stderr(65536).decode("utf-8", "replace"))

        rc = chan.recv_exit_status()
        chan.close()
        text = "".join(out)

        if self.tl:
            self.tl.event("win_cmd", status="ok" if rc == 0 else "fail",
                          detail={"rc": rc, "cmd": command[:160]})
        return rc, text

    def run_powershell(self, script, timeout=600):
        """Run a PowerShell script via -EncodedCommand.

        Base64/UTF-16LE rather than inline quoting: the QA's payloads contain
        quotes, ampersands and pipes, and cmd.exe would mangle them somewhere
        between here and PowerShell. It also keeps the script body out of the
        cmd.exe command line, though the encoded blob still appears in the
        4688 event — which is fine and in fact useful, since the script is
        detection bait we WANT the collection to find.
        """
        import base64
        # $ProgressPreference is load-bearing, not tidiness. PowerShell writes
        # progress records to the CLIXML stream, and over SSH that lands
        # INTERLEAVED with stdout — so `(Get-Service X).Status` came back as
        # several hundred bytes of <Objs Version="1.1.0.1">…</Objs> with the
        # actual word buried in it. Every service-state probe therefore read as
        # "not Running", and enrolment waited out its full timeout against a
        # client that was fine.
        script = "$ProgressPreference='SilentlyContinue'\n" + script
        blob = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        cmd = ("powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass "
               f"-EncodedCommand {blob}")
        return self.run(cmd, timeout=timeout)

    def msiexec(self, args, timeout=900):
        """Run msiexec and return its REAL exit code.

        Two traps, both of which made a failed install look like a clean one:

        * OpenSSH for Windows starts POWERSHELL here, not cmd.exe. Anything
          written in cmd syntax (`if not exist ... mkdir`, `&& echo`) fails to
          parse, and `&` produces a bare "AmpersandNotAllowed" parser error.
        * msiexec detaches. Invoked plainly it returns 0 within a fraction of a
          second whatever the outcome, so a 1603 fatal error was indistinguish-
          able from success and the phase went on to wait ten minutes for a
          client that was never going to appear.

        Start-Process -Wait -PassThru fixes both: PowerShell-native, blocks
        until msiexec exits, and hands back the actual code.
        """
        quoted = ",".join(
            "\"`\"" + a + "`\"\"" if a.startswith(("C:", "{", "\\")) else f"'{a}'"
            for a in args)
        rc, out = self.run_powershell(
            f"$p = Start-Process msiexec.exe -ArgumentList {quoted} "
            f"-Wait -PassThru; Write-Output ('QAVAL:' + $p.ExitCode + ':QAVAL')",
            timeout=timeout)
        m = re.search(r"QAVAL:(-?\d+):QAVAL", out or "")
        code = int(m.group(1)) if m else None
        if self.tl:
            # 0 = success, 3010 = success + reboot pending. Anything else is a
            # failure worth naming: 1603 fatal, 1618 another install running,
            # 1605 product not installed.
            self.tl.event("msiexec", status="ok" if code in (0, 3010) else "fail",
                          detail={"exit": code, "args": " ".join(args)[:160]})
        return code

    def ps_value(self, expression, timeout=120):
        """Evaluate a PowerShell expression and return just its value.

        Wraps the result in a sentinel and greps it back out, because even with
        the progress stream silenced, banners and warnings can share stdout.
        Returns None if the expression produced nothing.
        """
        script = (f"$v = ({expression});"
                  f"Write-Output ('QAVAL:' + [string]$v + ':QAVAL')")
        rc, out = self.run_powershell(script, timeout=timeout)
        if rc != 0:
            return None
        m = re.search(r"QAVAL:(.*?):QAVAL", out, re.S)
        if not m:
            return None
        val = m.group(1).strip()
        return val or None

    # --- files -----------------------------------------------------------

    def put(self, local_path, remote_path):
        c = self.connect()
        sftp = c.open_sftp()
        try:
            self._mkdirs(sftp, posixpath.dirname(remote_path.replace("\\", "/")))
            sftp.put(local_path, remote_path)
        finally:
            sftp.close()
        if self.tl:
            self.tl.ok("win_upload", detail={"to": remote_path})

    def put_text(self, text, remote_path):
        c = self.connect()
        sftp = c.open_sftp()
        try:
            self._mkdirs(sftp, posixpath.dirname(remote_path.replace("\\", "/")))
            with sftp.open(remote_path, "w") as fh:
                fh.write(text)
        finally:
            sftp.close()

    def exists(self, remote_path):
        c = self.connect()
        sftp = c.open_sftp()
        try:
            sftp.stat(remote_path)
            return True
        except IOError:
            return False
        finally:
            sftp.close()

    def remove(self, remote_path, recursive=False):
        """Best-effort delete. Teardown runs even when earlier phases failed,
        so a missing file is a no-op rather than an error."""
        c = self.connect()
        sftp = c.open_sftp()
        try:
            try:
                info = sftp.stat(remote_path)
            except IOError:
                return True                      # already gone
            if statmod.S_ISDIR(info.st_mode):
                if not recursive:
                    return False
                for entry in sftp.listdir(remote_path):
                    self.remove(posixpath.join(remote_path.replace("\\", "/"), entry),
                                recursive=True)
                sftp.rmdir(remote_path)
            else:
                sftp.remove(remote_path)
            return True
        except IOError:
            return False
        finally:
            sftp.close()

    @staticmethod
    def _mkdirs(sftp, path):
        """Create a remote directory tree, skipping the drive letter.

        Walking every component from the start would call sftp.mkdir("C:")
        first. Windows OpenSSH's SFTP resolves that relative to the session's
        home directory, so instead of failing it happily creates a literal
        directory named `C:` in the user's profile — junk that teardown does
        not know about because it is not under the staging directory.
        """
        if not path or path in ("/", "."):
            return
        parts = [p for p in path.split("/") if p]
        if not parts:
            return
        # A leading "C:" is a drive, not a directory to create.
        built = parts.pop(0) if re.match(r"^[A-Za-z]:$", parts[0]) else ""
        for p in parts:
            built = built + "/" + p if built else p
            try:
                sftp.mkdir(built)
            except IOError:
                pass          # already exists

    # --- facts -----------------------------------------------------------

    def facts(self):
        rc, out = self.run_powershell(
            "$os=Get-CimInstance Win32_OperatingSystem;"
            "$cs=Get-CimInstance Win32_ComputerSystem;"
            "[pscustomobject]@{host=$env:COMPUTERNAME;os=$os.Caption;"
            "ram_gb=[math]::Round($cs.TotalPhysicalMemory/1GB,1)}|ConvertTo-Json -Compress")
        if rc != 0:
            return {}
        import json
        import re
        m = re.search(r"\{.*\}", out, re.S)
        try:
            return json.loads(m.group(0)) if m else {}
        except (ValueError, AttributeError):
            return {}

    def service_state(self, name):
        """'Running' | 'Stopped' | None if the service does not exist."""
        return self.ps_value(
            f"Get-Service -Name '{name}' -ErrorAction SilentlyContinue "
            f"| Select-Object -ExpandProperty Status")

    def is_admin(self):
        rc, out = self.run_powershell(
            "$p=New-Object Security.Principal.WindowsPrincipal("
            "[Security.Principal.WindowsIdentity]::GetCurrent());"
            "Write-Output ('QAVAL:' + $p.IsInRole("
            "[Security.Principal.WindowsBuiltInRole]::Administrator) + ':QAVAL')")
        m = re.search(r"QAVAL:(.*?):QAVAL", out or "", re.S)
        return rc == 0 and bool(m) and "true" in m.group(1).strip().lower()
