"""Memory-forensics module.

End-to-end pipeline that mirrors the agentic/aws/azure pattern:
acquire a Windows memory image via Velociraptor, push it to the
in-tree VolWeb stack, run Volatility 3 plugins + yarascan, then ask
an LLM to synthesise the findings into an engagement-ready markdown
report.

Three analysis modes share the same plumbing:

  * ``yara``     — yarascan hits only; cheapest, fast triage at scale.
  * ``plugin``   — curated Vol3 plugin output only; behavioural
                   context without a signature corpus.
  * ``layered``  — both signals fed to one LLM with a tiered prompt;
                   default for deep analysis.

The public entry point is :func:`services.memory.pipeline.run_memory_pipeline`,
called from :mod:`routes.memory_routes`.  Everything else (acquire,
upload, extract, yarascan, cleanup) is an implementation detail of
that pipeline.
"""
