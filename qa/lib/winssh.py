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

import io
import posixpath
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
        blob = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        cmd = ("powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass "
               f"-EncodedCommand {blob}")
        return self.run(cmd, timeout=timeout)

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
        if not path or path in ("/", "."):
            return
        parts, built = path.split("/"), ""
        for p in parts:
            if not p:
                continue
            built = built + "/" + p if built else p
            try:
                sftp.mkdir(built)
            except IOError:
                pass          # exists, or a drive root like C:

    # --- facts -----------------------------------------------------------

    def is_admin(self):
        rc, out = self.run_powershell(
            "$p=New-Object Security.Principal.WindowsPrincipal("
            "[Security.Principal.WindowsIdentity]::GetCurrent());"
            "$p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)")
        return rc == 0 and "true" in out.lower()

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
        rc, out = self.run_powershell(
            f"(Get-Service -Name '{name}' -ErrorAction SilentlyContinue).Status")
        if rc != 0:
            return None
        val = out.strip().splitlines()
        val = val[-1].strip() if val else ""
        return val or None
