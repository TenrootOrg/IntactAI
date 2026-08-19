"""Phases that touch the Windows endpoint: enrolment, the malicious activity
that gives the collection something to find, and teardown.

SSH is used here and nowhere else. Enrolment installs the Velociraptor client
and teardown removes it; the activity in between is run over SSH only because
it is the *stimulus*, not the thing under test. Everything the platform is
supposed to do — collect, detect, ingest, analyse — goes through the product.
"""

import os
import posixpath
import time

from lib import clients as clients_lib, winssh

# Where the QA stages its own files on the target. One directory, so teardown
# is a single recursive delete and there is no doubt about what to remove.
#
# Two spellings of the same path, deliberately: SFTP wants forward slashes,
# while cmd.exe mishandles them for mkdir and for quoted msiexec arguments.
STAGE_DIR = "C:/Windows/Temp/intact-qa"
STAGE_DIR_WIN = STAGE_DIR.replace("/", "\\")

# The distinctive string the fake malicious script writes into memory. Phase 6
# asserts a yara rule matching THIS string fires — one targeted rule instead of
# a ruleset, so a miss is a real bug rather than an ambiguous result.
YARA_CANARY = "INTACT-QA-MEMORY-CANARY-7f3a91"


def register(runner, cfg):
    # enrol / activity / teardown drive a Windows box over SSH and cannot mean
    # anything without one. Not registering them at all is better than
    # registering and failing: runner._unmet then reports every dependant as
    # "enrol did not run" in the report's "Not reached" table, which is the
    # truth, instead of a cascade of red for a machine nobody asked for.
    #
    # The Linux profile enrols the appliance itself instead — see
    # qa/phases/endpoint_linux.py.
    if not cfg.windows_enabled:
        return

    tl = runner.ctx.tl

    def target():
        return winssh.WindowsTarget(cfg.windows_host, cfg.windows_user,
                                    cfg.windows_password, cfg.ssh_port, tl=tl)

    # ----------------------------------------------------------------- 2 --
    @runner.phase("enrol", "Install the Velociraptor client and wait for it",
                  needs=("auth",), critical=True)
    def enrol(ctx):
        c = ctx.get("client")
        detail = {}

        before = clients_lib._client_ids(c)
        detail["clients_before"] = len(before)

        # The platform generates the installer; the QA must use that one rather
        # than building its own, because the generated installer is the thing
        # operators actually run and the thing most likely to be broken.
        installer = _download_installer(c, ctx.run_dir, tl)
        ctx.check("platform produced a Windows installer", bool(installer),
                  actual=installer and os.path.basename(installer))
        if not installer:
            return detail
        detail["installer"] = os.path.basename(installer)
        detail["installer_bytes"] = os.path.getsize(installer)

        remote = f"{STAGE_DIR}/{os.path.basename(installer)}"
        remote_win = remote.replace("/", "\\")
        with target() as win:
            # UPLOAD FIRST, then uninstall, then install.
            #
            # The order is load-bearing. Removing the old client has to be done
            # with the package file in hand (see _uninstall_client), so the MSI
            # must already be on the box. Uninstalling first and uploading
            # afterwards left the product half-registered and made the install
            # fail 1603.
            #
            # PowerShell, not cmd: OpenSSH for Windows starts powershell.exe
            # here, so `if not exist ... mkdir` is a parse error, not a mkdir.
            win.run_powershell(
                f"New-Item -ItemType Directory -Force -Path '{STAGE_DIR_WIN}' "
                f"| Out-Null")
            win.put(installer, remote)
            ctx.check("installer uploaded", win.exists(remote))

            # Any client already here is from an earlier session and holds the
            # PREVIOUS server's CA — a fresh install regenerates it, so that
            # client can never enrol. Left in place the symptom is the worst
            # kind: service Running, installer "succeeded", client never
            # appears, phase waits out its whole timeout.
            pre = _uninstall_client(win, msi_path_win=remote_win)
            detail["preexisting_client_removed"] = pre
            if pre:
                tl.warn("stale_client_removed", detail={
                    "note": "target already had a Velociraptor client holding "
                            "the old CA; removed so enrolment is genuinely fresh"})

            code = win.msiexec(["/i", remote_win, "/quiet", "/norestart"])
            detail["install_exit"] = code
            # 0 = success, 3010 = success + reboot pending. 1603 is the fatal
            # one and used to be invisible because msiexec detaches.
            ctx.check("client installer succeeded", code in (0, 3010),
                      expected="0 or 3010", actual=code,
                      note="1603 usually means a previous install is still "
                           "registered; 1618 means another msiexec is running")

            state, _ = None, None
            for _ in range(30):
                state = win.service_state("Velociraptor")
                if state == "Running":
                    break
                time.sleep(2)
            ctx.check("Velociraptor service is running on the target",
                      state == "Running", expected="Running", actual=state)

        # Poll the PLATFORM, not the endpoint. The service running locally is
        # not the same as the server having accepted the enrolment, and it is
        # the server side that every later phase depends on.
        new_client, _ = tl.wait(
            "the new client to appear in Velociraptor",
            timeout_s=600, poll_s=10,
            probe=lambda: clients_lib._first_new_client(c, before),
            describe=lambda cid: cid)

        ctx.check("client enrolled and visible to the platform", bool(new_client),
                  actual=new_client)
        if new_client:
            ctx.set(client_id=new_client)
            detail["client_id"] = new_client
            detail["hostname"] = clients_lib._client_hostname(c, new_client)
        return detail

    # ----------------------------------------------------------------- 3 --
    @runner.phase("activity", "Clear the event logs, then run detection bait",
                  needs=("enrol",))
    def activity(ctx):
        """Clearing the logs first is what makes phase 5 both fast and
        deterministic: the exported .evtx is tiny and contains ONLY
        QA-generated events, so a detection that fires is unambiguously ours
        rather than pre-existing noise.

        The payload is SIMULATED malicious behaviour — an encoded command, a
        suspicious parent/child chain, and an RWX allocation to trip Malfind.
        It is detection bait, not malware, and must stay that way.
        """
        detail = {}
        with target() as win:
            rc, out = win.run_powershell(
                "Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | "
                "Where-Object { $_.RecordCount -gt 0 } | ForEach-Object { "
                "  try { [System.Diagnostics.Eventing.Reader.EventLogSession]"
                "::GlobalSession.ClearLog($_.LogName) } catch {} }; "
                "'CLEARED'")
            detail["cleared"] = "CLEARED" in out
            ctx.check("event logs cleared before the bait ran",
                      "CLEARED" in out, actual=ctx.redact(out)[-160:],
                      note="keeps the collected .evtx small and unambiguous")

            rc, out = win.run_powershell(_BAIT_SCRIPT.replace(
                "@@CANARY@@", YARA_CANARY).replace("@@STAGE@@", STAGE_DIR_WIN))
            detail["bait_rc"] = rc
            detail["canary"] = YARA_CANARY
            ctx.check("detection bait ran", rc == 0,
                      actual=ctx.redact(out)[-300:])
            ctx.check("bait reported its memory canary in place",
                      YARA_CANARY in out, note="phase 6's yara rule matches this")

            # Confirm the events we want actually exist, so a later empty
            # collection is attributable to collection rather than to nothing
            # having happened.
            rc, out = win.run_powershell(
                "(Get-WinEvent -LogName 'Windows PowerShell' -MaxEvents 50 "
                "-ErrorAction SilentlyContinue | Measure-Object).Count")
            count = _first_int(out)
            detail["powershell_events"] = count
            ctx.check("the bait produced event-log records", (count or 0) > 0,
                      expected=">0", actual=count)

        ctx.set(yara_canary=YARA_CANARY)
        return detail

    # ----------------------------------------------------------------- F --
    @runner.phase("teardown", "Remove the client and everything the QA left",
                  needs=("enrol",), optional=True)
    def teardown(ctx):
        """Runs after log collection so nothing needed for the report is
        destroyed first, and before the report so teardown problems appear in
        it.

        Order matters: clean the artifacts while the agent still exists, THEN
        remove the agent. After the uninstall there is no way back in.

        Every step is best-effort and idempotent — if enrolment failed there is
        nothing to remove, and that is a no-op rather than an error.
        """
        detail = {"removed": [], "left_behind": []}
        c = ctx.get("client")

        try:
            with target() as win:
                # 1. artifacts first, while there is still a way in
                for path in (STAGE_DIR,):
                    ok = win.remove(path, recursive=True)
                    (detail["removed"] if ok else detail["left_behind"]).append(path)

                # The memory image is the biggest and most dangerous thing left
                # on the box — multi-GB of plaintext credentials scraped from
                # RAM. Unless the operator asked to keep it, it goes.
                if not cfg.keep_memory:
                    for path in ctx.get("memory_image_paths", []):
                        ok = win.remove(path)
                        (detail["removed"] if ok else
                         detail["left_behind"]).append(path)

                # 2. uninstall. Fire-and-forget BY NATURE: the agent kills its
                # own service, so this call cannot return a clean success.
                # Confirm by watching the client go offline, never by exit code.
                detail["uninstalled"] = _uninstall_client(win)

                state = win.service_state("Velociraptor")
                detail["service_after"] = state
                ctx.check("Velociraptor service is gone from the target",
                          state is None, expected="absent", actual=state,
                          note="a surviving agent means the next QA run finds a "
                               "stale client instead of enrolling fresh")
        except Exception as exc:                              # noqa: BLE001
            # Teardown failure is a QA finding in its own right, but it must
            # never mask an earlier failure.
            ctx.check("teardown reached the Windows target", False,
                      actual=ctx.redact(str(exc))[:200])

        # 3. Confirm server-side that the client is really gone.
        #
        # There is no delete-client API: /api/client/<id> is a stub that returns
        # 501. So this verifies rather than removes, and asks for OFFLINE
        # clients too — the default list is online-only, so an agent that was
        # merely stopped rather than uninstalled would vanish from it and read
        # as a clean teardown.
        client_id = ctx.get("client_id")
        if client_id and c:
            still_there = client_id in clients_lib._client_ids(c, include_offline=True)
            detail["server_record"] = "present" if still_there else "gone"
            # NOT a check. There is no delete-client API — /api/client/<id> is
            # a 501 stub — so the record surviving is a platform limitation the
            # harness cannot act on, not a QA defect. Failing the run for it
            # made every otherwise-clean run red, which is how a report stops
            # being read. Reported as a warning and carried into the report so
            # it is visible without being fatal.
            if still_there:
                tl.warn("client_record_remains", detail={
                    "client_id": client_id,
                    "note": "the agent is uninstalled but Velociraptor still "
                            "lists the client; remove it in the Velociraptor "
                            "UI if a stale entry matters"})

        detail["windows_left_clean"] = not detail["left_behind"]
        return detail


# --- the bait ------------------------------------------------------------
#
# Simulated malicious behaviour, chosen so each item maps to something a later
# phase asserts:
#
#   encoded command      -> event-log detection, Timesketch (phase 5)
#   suspicious child     -> process-tree finding, blueprint hunt (phase 4)
#   RWX allocation       -> Malfind, VolWeb (phase 6)
#   canary string in RAM -> the single yara rule (phase 6)
#
# It allocates and writes; it does not persist, spread, or contact anything.
_BAIT_SCRIPT = r"""
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path '@@STAGE@@' | Out-Null

# 1. Encoded command -- the classic obfuscation signal. Runs a harmless echo.
$inner = "Write-Output 'intact-qa-encoded-command'"
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner))
powershell.exe -NoProfile -EncodedCommand $enc | Out-Null

# 2. Suspicious parent/child: powershell spawning cmd spawning whoami.
Start-Process -FilePath 'cmd.exe' -ArgumentList '/c whoami & hostname' `
    -WindowStyle Hidden -Wait

# 3. An RWX allocation holding a recognisable string, so Malfind has something
#    real to find and the yara rule has something real to match. The memory is
#    deliberately kept alive by a reference for the life of the process.
$sig = @'
using System;
using System.Runtime.InteropServices;
public class QAAlloc {
  [DllImport("kernel32")] public static extern IntPtr VirtualAlloc(
      IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
  [DllImport("kernel32")] public static extern void RtlMoveMemory(
      IntPtr dest, byte[] src, uint length);
}
'@
Add-Type -TypeDefinition $sig -ErrorAction SilentlyContinue

$canary = '@@CANARY@@'
$bytes  = [Text.Encoding]::ASCII.GetBytes(($canary * 64))
# 0x3000 = MEM_COMMIT|MEM_RESERVE, 0x40 = PAGE_EXECUTE_READWRITE
$mem = [QAAlloc]::VirtualAlloc([IntPtr]::Zero, [uint32]$bytes.Length, 0x3000, 0x40)
if ($mem -ne [IntPtr]::Zero) {
    [QAAlloc]::RtlMoveMemory($mem, $bytes, [uint32]$bytes.Length)
    Write-Output "RWX_ALLOC_OK @@CANARY@@"
} else {
    Write-Output "RWX_ALLOC_FAILED"
}

# Hold the process (and therefore the allocation) briefly so the memory
# acquisition in phase 6 has a live target rather than a freed page.
Start-Process powershell.exe -ArgumentList @(
    '-NoProfile','-WindowStyle','Hidden','-Command',
    "`$c='@@CANARY@@'; `$b=[Text.Encoding]::ASCII.GetBytes(`$c*64); Start-Sleep -Seconds 3600"
) | Out-Null

Write-Output 'BAIT_COMPLETE'
"""


# --- helpers -------------------------------------------------------------


def _uninstall_client(win, msi_path_win=None):
    """Remove any installed Velociraptor client. Returns True if one was there.

    Uninstall BY PACKAGE FILE when one is available, not by product code.

    Uninstalling by code left the product half-registered on this target:
    Windows Installer still had Velociraptor 0.77.1 recorded, with a cached
    source path pointing at a package that no longer existed. The next `/i`
    was therefore treated as a RECONFIGURE, went looking for that missing
    source, failed SecureRepair and returned 1603 — while the service was
    gone, so every symptom pointed at the install rather than at the leftover
    registration. Handing msiexec the actual .msi gives it a valid source and
    makes the removal complete.

    Idempotent and best-effort: teardown runs even when earlier phases failed,
    so "nothing to remove" is a normal outcome rather than an error. Success is
    judged by the service being GONE, never by an exit code — the agent stops
    its own service, so the call cannot report cleanly.
    """
    installed = (win.service_state("Velociraptor") is not None
                 or win.exists("C:/Program Files/Velociraptor")
                 or bool(win.ps_value(
                     "Get-CimInstance Win32_Product "
                     "-Filter \"Name LIKE 'Velociraptor%'\" "
                     "| Select-Object -First 1 -ExpandProperty IdentifyingNumber")))
    if not installed:
        return False

    win.run_powershell("Stop-Service -Name Velociraptor -Force "
                       "-ErrorAction SilentlyContinue", timeout=120)

    if msi_path_win:
        win.msiexec(["/x", msi_path_win, "/quiet", "/norestart"])
    else:
        code = win.ps_value(
            "Get-CimInstance Win32_Product -Filter \"Name LIKE 'Velociraptor%'\" "
            "| Select-Object -First 1 -ExpandProperty IdentifyingNumber")
        if code:
            win.msiexec(["/x", code, "/quiet", "/norestart"])

    win.run_powershell("sc.exe delete Velociraptor 2>&1 | Out-Null", timeout=60)
    # The writeback file holds the client_id. Leaving it behind would let a
    # reinstalled client re-adopt the old identity instead of enrolling fresh.
    win.remove("C:/Program Files/Velociraptor", recursive=True)
    return True


def _download_installer(c, run_dir, tl, platform="windows-msi"):
    """Fetch the platform-generated client installer.

    'windows-msi', not 'windows' — the route's platform vocabulary is
    windows-msi / windows-exe / linux / mac, and anything else 404s. Verified
    against a live box: windows-msi serves a 27 MB MSI, while 'windows' and
    'windows-exe' both 404 (only the MSI and the Linux build are pre-generated
    into client_installers/ at velociraptor container startup).
    """
    url = f"/api/clients/download/{platform}"
    try:
        r = c.s.get(c.base + url, timeout=300, stream=True)
    except Exception as exc:                                  # noqa: BLE001
        tl.fail("installer_download_failed", detail=str(exc)[:200])
        return None
    if r.status_code != 200:
        tl.fail("installer_download_failed", detail={"status": r.status_code})
        return None

    name = "velociraptor-client.msi"
    disp = r.headers.get("content-disposition", "")
    if "filename=" in disp:
        name = disp.split("filename=")[-1].strip('"; ')

    path = os.path.join(run_dir, "artifacts", name)
    with open(path, "wb") as fh:
        for chunk in r.iter_content(65536):
            fh.write(chunk)
    tl.ok("installer_downloaded",
          detail={"file": name, "bytes": os.path.getsize(path)})
    return path


def _first_int(text):
    import re
    m = re.search(r"\d+", text or "")
    return int(m.group(0)) if m else None
