"""CVE Scan service.

Ports the standalone `nvd_check.py` side project into IntactAI:
ingests Velociraptor / DetectRaptor CSV exports, matches every
installed product/version pair against NVD's CVE database, writes
a consolidated `combined_cves.csv` (one row per host × product ×
CVE) plus a structured `findings.json` and a short markdown summary
that the Engagement Report builder can consume.

Public entry point: `run_cve_scan(run_id, input_csv_paths, …)`.
"""

from .pipeline import run_cve_scan, pull_from_velociraptor

__all__ = ['run_cve_scan', 'pull_from_velociraptor']
