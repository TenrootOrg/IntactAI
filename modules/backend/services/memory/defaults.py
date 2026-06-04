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
# 12 plugins that gave the best signal in the PoC's 3-way comparison on
# DESKTOP-566AT85. The full available-plugin catalog from VolWeb is 68
# entries; most are low-signal for an LLM (driver/IRP/kernel inventory,
# bootkey-dependent stuff that fails on Win10) or duplicative.
#
# Deliberately EXCLUDES ``HollowProcesses``: that plugin walks every
# process's VAD tree and SHA-256s each executable page against on-disk
# file hashes. Observed runtime on a 3-5 GB Win10/11 dump: 12+ minutes.
# It is the only plugin that has ever monopolised the Celery worker for
# longer than the rest combined. ``Hollowfind`` (a cheaper structural
# check) is also dropped from the default set; if an operator wants it
# they can add it via a custom blueprint.
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
    "volatility3.plugins.windows.registry.printkey.PrintKey",
)

# Per-plugin row cap used when assembling the LLM prompt.
#
# A Win10 dump's malfind/dlllist easily produce hundreds of rows; the
# LLM only needs a representative slice. 80 rows per plugin × 12
# plugins ≈ 950 rows ≈ 80-150 KB JSON = ~25K tokens — well under the
# Opus context window and the price-vs-signal sweet spot the PoC
# settled on.
DEFAULT_MAX_ROWS_PER_PLUGIN: int = 80

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
    "cpu_limit": 80,               # percentage on the target host
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
# 2.0 is the safety floor; the 8 GiB default mem_estimate combined
# with the 3x cap was over-conservative (required 24 GB free for a
# host that produces a 3 GB dump). 2.0 × 8 GiB = 16 GB free which
# comfortably covers worst-case + headroom.
DISK_PREFLIGHT_MULTIPLIER: float = 2.0
