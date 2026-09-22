"""Constants for the memory-forensics pipeline.

Single source of truth for the curated plugin list, row caps, and
Velociraptor acquisition parameters. Lifted from the validated
``~/volweb-poc/`` PoC and tagged with the lessons that justified each
value so they don't get tweaked carelessly.
"""

# ---------------------------------------------------------------------------
# Volatility 3 — curated plugin list
# ---------------------------------------------------------------------------
#
# 11 plugins that gave the best signal in the PoC's 3-way comparison on
# DESKTOP-566AT85. The full available-plugin catalog from VolWeb is 68
# entries; most are low-signal for an LLM (driver/IRP/kernel inventory,
# bootkey-dependent stuff that fails on Win10) or duplicative.
#
# Deliberately EXCLUDES ``HollowProcesses``: that plugin walks every
# process's VAD tree and SHA-256s each executable page against on-disk
# file hashes. Observed runtime on a 3-5 GB Win10/11 dump: 12+ minutes.
# It is the only plugin that has ever monopolised the Celery worker for
# longer than the rest combined. ``Hollowfind`` (a cheaper structural
# check) is also dropped from the default set — and in any case VolWeb
# 3.16.0 does not register Hollowfind at all, so it could not run if it
# were listed; if an operator wants HollowProcesses they can add it via a
# custom blueprint.
CURATED_PLUGINS: tuple[str, ...] = (
    # Process discovery + lineage
    "volatility3.plugins.windows.pslist.PsList",
    "volatility3.plugins.windows.psscan.PsScan",
    "volatility3.plugins.windows.pstree.PsTree",
    "volatility3.plugins.windows.cmdline.CmdLine",
    "volatility3.plugins.windows.dlllist.DllList",
    # Injection / malware indicators
    "volatility3.plugins.windows.malfind.Malfind",
    # Persistence + services
    "volatility3.plugins.windows.svcscan.SvcScan",
    "volatility3.plugins.windows.mutantscan.MutantScan",
    # Network
    "volatility3.plugins.windows.netscan.NetScan",
    "volatility3.plugins.windows.netstat.NetStat",
    # Registry / execution history
    "volatility3.plugins.windows.registry.userassist.UserAssist",
    # PrintKey was the 12th entry and never once ran: VolWeb 3.16.0 does not
    # register `registry.printkey.PrintKey` in volweb_plugins.json, so the
    # engine dropped it from the list without a row or an error and every log
    # line since has counted out of a 12 that could only ever reach 11.
    # Removed rather than substituted — `registry.scheduled_tasks.
    # ScheduledTasks` and `registry.amcache.Amcache` are the registered
    # registry plugins if an operator wants that signal back, via a blueprint.
)

# ---------------------------------------------------------------------------
# Volatility 3 — full catalog of Windows plugins surfaced to the UI
# ---------------------------------------------------------------------------
#
# Used by the Blueprints page's memory editor to render a checkbox grid
# (operator picks plugins by ticking boxes instead of typing dotted
# class paths) AND to expand the `['*']` all-plugins marker at dispatch.
#
# This is a VERBATIM mirror of what VolWeb will actually run: the union of
# `volatility_engine/volweb_plugins.json` + `volweb_misc.json` inside the
# forensicxlab/volweb-backend image, windows section, grouped by VolWeb's own
# category labels. It is NOT "every Vol3 plugin that exists".
#
# That distinction is load-bearing. engine.py:start_selective_extraction
# filters the requested list against those two registries
# (`main_selected = [p for p in selected_plugins if p in all_main]`) and
# SILENTLY DROPS anything else — no row, no error, no log line. The previous
# hand-written catalog carried 12 names VolWeb 3.16.0 does not register
# (handles.Handles, hollowfind.Hollowfind, hashdump.Hashdump, lsadump.Lsadump,
# registry.printkey.PrintKey, mftscan.MFTScan, memmap.Memmap, statistics.
# Statistics, vadinfo.VadInfo, vadwalk.VadWalk, virtmap.VirtMap,
# registry.cmdline.CmdLine) and was missing 36 that it does — so the operator
# ticked boxes for plugins that could never run, and the shipped "Credentials"
# blueprint (Hashdump + Lsadump + Cachedump) ran exactly ONE of its three.
# Verified 2026-09-22 against the image on this appliance
# (forensicxlab/volweb-backend:3.16.0): 66 main + 2 misc = 68 windows plugins.
#
# Re-derive after a VolWeb bump, don't hand-edit:
#   docker cp intact_volweb_backend:/home/app/web/volatility_engine/volweb_plugins.json -
# tests/test_memory_symbols_airgap.py fails if CURATED_PLUGINS or any shipped
# blueprint names something outside this catalog.
KNOWN_VOL3_PLUGINS: tuple[tuple[str, str], ...] = (
    # ── Processes ──
    ("Processes", "volatility3.plugins.windows.cmdline.CmdLine"),
    ("Processes", "volatility3.plugins.windows.debugregisters.DebugRegisters"),
    ("Processes", "volatility3.plugins.windows.dlllist.DllList"),
    ("Processes", "volatility3.plugins.windows.envars.Envars"),
    ("Processes", "volatility3.plugins.windows.joblinks.JobLinks"),
    ("Processes", "volatility3.plugins.windows.ldrmodules.LdrModules"),
    ("Processes", "volatility3.plugins.windows.mutantscan.MutantScan"),
    ("Processes", "volatility3.plugins.windows.orphan_kernel_threads.Threads"),
    ("Processes", "volatility3.plugins.windows.privileges.Privs"),
    ("Processes", "volatility3.plugins.windows.pslist.PsList"),
    ("Processes", "volatility3.plugins.windows.psscan.PsScan"),
    ("Processes", "volatility3.plugins.windows.pstree.PsTree"),
    ("Processes", "volatility3.plugins.windows.registry.amcache.Amcache"),
    ("Processes", "volatility3.plugins.windows.sessions.Sessions"),
    ("Processes", "volatility3.plugins.windows.suspended_threads.SuspendedThreads"),
    ("Processes", "volatility3.plugins.windows.svclist.SvcList"),
    ("Processes", "volatility3.plugins.windows.svcscan.SvcScan"),
    ("Processes", "volatility3.plugins.windows.thrdscan.ThrdScan"),
    ("Processes", "volatility3.plugins.windows.threads.Threads"),

    # ── Malware ──
    ("Malware", "volatility3.plugins.windows.cmdscan.CmdScan"),
    ("Malware", "volatility3.plugins.windows.consoles.Consoles"),
    ("Malware", "volatility3.plugins.windows.direct_system_calls.DirectSystemCalls"),
    ("Malware", "volatility3.plugins.windows.hollowprocesses.HollowProcesses"),
    ("Malware", "volatility3.plugins.windows.iat.IAT"),
    ("Malware", "volatility3.plugins.windows.indirect_system_calls.IndirectSystemCalls"),
    ("Malware", "volatility3.plugins.windows.malfind.Malfind"),
    ("Malware", "volatility3.plugins.windows.processghosting.ProcessGhosting"),
    ("Malware", "volatility3.plugins.windows.psxview.PsXView"),
    ("Malware", "volatility3.plugins.windows.ssdt.SSDT"),
    ("Malware", "volatility3.plugins.windows.suspicious_threads.SuspiciousThreads"),
    ("Malware", "volatility3.plugins.windows.unhooked_system_calls.unhooked_system_calls"),
    ("Malware", "volatility3.plugins.windows.verinfo.VerInfo"),

    # ── Kernel ──
    ("Kernel", "volatility3.plugins.windows.callbacks.Callbacks"),
    ("Kernel", "volatility3.plugins.windows.devicetree.DeviceTree"),
    ("Kernel", "volatility3.plugins.windows.driverirp.DriverIrp"),
    ("Kernel", "volatility3.plugins.windows.drivermodule.DriverModule"),
    ("Kernel", "volatility3.plugins.windows.driverscan.DriverScan"),
    ("Kernel", "volatility3.plugins.windows.modscan.ModScan"),
    ("Kernel", "volatility3.plugins.windows.modules.Modules"),
    ("Kernel", "volatility3.plugins.windows.svcdiff.SvcDiff"),
    ("Kernel", "volatility3.plugins.windows.timers.Timers"),
    ("Kernel", "volatility3.plugins.windows.unloadedmodules.UnloadedModules"),

    # ── Network ──
    ("Network", "volatility3.plugins.windows.netscan.NetScan"),
    ("Network", "volatility3.plugins.windows.netstat.NetStat"),

    # ── Registry ──
    ("Registry", "volatility3.plugins.windows.registry.certificates.Certificates"),
    ("Registry", "volatility3.plugins.windows.registry.getcellroutine.GetCellRoutine"),
    ("Registry", "volatility3.plugins.windows.registry.hivelist.HiveList"),
    ("Registry", "volatility3.plugins.windows.registry.hivescan.HiveScan"),
    ("Registry", "volatility3.plugins.windows.registry.scheduled_tasks.ScheduledTasks"),
    ("Registry", "volatility3.plugins.windows.registry.userassist.UserAssist"),

    # ── Security ──
    ("Security", "volatility3.plugins.windows.cachedump.Cachedump"),
    ("Security", "volatility3.plugins.windows.getservicesids.GetServiceSIDs"),
    ("Security", "volatility3.plugins.windows.getsids.GetSIDs"),
    ("Security", "volatility3.plugins.windows.registry.hashdump.Hashdump"),
    ("Security", "volatility3.plugins.windows.registry.lsadump.Lsadump"),
    ("Security", "volatility3.plugins.windows.skeleton_key_check.Skeleton_Key_Check"),
    ("Security", "volatility3.plugins.windows.truecrypt.Passphrase"),

    # ── Filesystem ──
    ("Filesystem", "volatility3.plugins.windows.filescan.FileScan"),
    ("Filesystem", "volatility3.plugins.windows.mbrscan.MBRScan"),
    ("Filesystem", "volatility3.plugins.windows.mftscan.ADS"),
    ("Filesystem", "volatility3.plugins.windows.mftscan.ResidentData"),
    ("Filesystem", "volatility3.plugins.windows.shimcachemem.ShimcacheMem"),
    ("Filesystem", "volatility3.plugins.windows.symlinkscan.SymlinkScan"),

    # ── GUI ──
    ("GUI", "volatility3.plugins.windows.deskscan.DeskScan"),
    ("GUI", "volatility3.plugins.windows.desktops.Desktops"),
    ("GUI", "volatility3.plugins.windows.windows.Windows"),
    ("GUI", "volatility3.plugins.windows.windowstations.WindowStations"),

    # ── Other ──
    ("Other", "volatility3.plugins.windows.info.Info"),
)


# Per-plugin row cap used when assembling the LLM prompt.
#
# A Win10 dump's malfind/dlllist easily produce hundreds of rows. Each
# plugin's rows are SEVERITY-ORDERED (analyzers._row_severity) BEFORE
# truncating to this cap, so the slice we keep is the highest-signal
# rows (RWX/injected memory, LOLBins, suspicious paths, established
# connections) — not the first N in the plugin's native order. That
# makes the truncation safe to widen: raised 80 → 250 on 2026-06-17
# after a run produced a narrow report. 250 × ~9-12 emitting plugins
# still sits under PROMPT_BYTE_GUARD, which truncates anything over
# 350 KB as a final backstop.
DEFAULT_MAX_ROWS_PER_PLUGIN: int = 250

# Per-hit cap for yarascan output handed to the LLM.
#
# A clean Win10 dump matches a handful of rules in the noisy slice of
# the corpus (REDLEAVES IPC string FP, etc.); a compromised host with
# operator tooling staged in PowerShell ISE hit 33 unique offsets
# across 10 distinct rules in the PoC. 500 is conservative — leaves
# room for noisier dumps without exceeding the byte guard below.
DEFAULT_MAX_YARA_HITS: int = 500

# Hard upper bound on the assembled LLM prompt in bytes. Above this we
# truncate with a visible marker rather than letting the model silently
# drop content or the request to fail at the API layer.
PROMPT_BYTE_GUARD: int = 350_000

# ---------------------------------------------------------------------------
# YARA scan scoping — threat-type categories
# ---------------------------------------------------------------------------
#
# A blueprint can narrow the yarascan from the full corpus to a few
# threat types via ``settings.yara_categories``. That cuts the heavy
# step (compile + page-walk all 1,467 seeded rules) down to a focused
# subset — faster, lighter on the yarascan worker, and fewer false
# positives — at the cost of breadth. So only the FOCUSED blueprints
# scope; the broad-net ones (Curated standard, the dedicated YARA-only
# sweep, the all-plugins deep dive) leave it empty = scan everything.
#
# Why substring-on-name and not ruleset/prefix: the two seeded sources
# name rules with INCOMPATIBLE schemes. Neo23x0 signature-base prefixes
# by threat type (MAL_/APT_/HKTL_/WEBSHELL_/EXPL_…); Elastic prefixes by
# PLATFORM (Windows_/Linux_/MacOS_) with the threat type as the SECOND
# token (Windows_Ransomware_…). A leading-token match can't categorise
# both, but a case-insensitive substring on the rule NAME catches the
# threat word wherever it sits. Each category below maps to the
# substrings that select its rules; the pipeline unions the keywords for
# the blueprint's chosen categories and resolves them to rule IDs at run
# time (volweb_client.resolve_yara_rule_ids). Empty / missing / ['*']
# means "scan the full corpus".
#
# Validated match counts on the install-time corpus (1,467 active rules):
#   ransomware 105 · hacktool 120 · webshell 16 · apt 108 ·
#   trojan/rat 399 · exploit/vuln 201 · stealer 33
YARA_CATEGORY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "ransomware": ("ransom",),
    "hacktool":   ("hacktool", "hktl", "mimikatz", "cobalt", "metasploit",
                   "meterpreter", "rubeus", "sharphound", "bloodhound"),
    "webshell":   ("webshell",),
    "apt":        ("apt_", "_apt_", "sofacy", "lazarus", "equation",
                   "turla", "winnti", "kimsuky"),
    "trojan":     ("trojan", "_rat_", "backdoor", "_bot_", "implant"),
    "exploit":    ("expl_", "exploit", "_cve_", "vuln"),
    "stealer":    ("stealer", "infostealer", "keylog", "passworddump"),
}

# ---------------------------------------------------------------------------
# Velociraptor — Windows.Memory.Acquisition kwargs
# ---------------------------------------------------------------------------
#
# Default knobs handed to ``collect_client()``. Two values are
# load-bearing and must not change without re-validating the pipeline:
#
#   * ``max_bytes=68719476736`` (64 GiB) — the VQL kwarg is ``max_bytes``
#     (NOT ``max_upload_bytes`` which is the field on the compiled
#     request; passing the latter is silently ignored and you get the
#     server's default 1 GiB cap, which truncates the high-address
#     kernel pages on any host with >1 GiB RAM. Vol3's pdbscan then
#     fails with "No suitable kernels found" and the entire downstream
#     analysis is junk.).
#
#   * ``Compression='None'`` — the artifact spec wraps memory pages in
#     S2/Snappy/Gzip when set. With ``'None'`` the fs-accessor extract
#     delivers raw memory and Vol3 reads it directly. Anything else
#     requires an inner-layer decode step we deliberately removed.
ACQUISITION_DEFAULTS: dict = {
    "max_bytes": 68_719_476_736,   # 64 GiB cap
    "cpu_limit": 50,               # percentage on the target host
    "compression": "None",         # MUST stay None — see comment above
    "urgent": True,                # ask Velociraptor to schedule ahead of routine work
}

# Disk pre-flight multiplier — refuse to dispatch acquisition unless
# the host has ``mem_bytes_estimate * THIS`` bytes free on the volume
# that backs the host dump dir + VolWeb's media volume + Velociraptor's
# filestore.
#
# Empirical footprint during a real acquisition (PoC, 4 GiB Win11 VM):
#   * host .raw                           ~3 GB
#   * Velociraptor server-side (zlib)     ~1.5 GB
#   * VolWeb media copy                   ~3 GB
#   total transient peak                  ~7.5 GB  (~2x the dump size)
#
# 1.5 is the practical floor — covers the three-copy worst-case
# above with a 50% margin, which is enough for the 4 GiB default
# mem_estimate (= 6 GiB required free). 2.0 was over-conservative
# on small-RAM hosts (< 4 GiB free on a 90% full disk would block
# every memory run). The shared-volume fast-path also halves the
# real transient footprint by skipping the docker-cp middle step,
# so 1.5 has a real margin even without it.
DISK_PREFLIGHT_MULTIPLIER: float = 1.5
