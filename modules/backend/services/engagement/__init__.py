"""Engagement reporting library — now used by the case (fusion) report layer.

The standalone engagement builder was retired (its report is produced at the case
level). What remains is the shared, reusable reporting toolkit imported directly
by ``services.fusion``:

  - ``pdf.render_engagement_pdf`` — branded WeasyPrint PDF rendering.
  - ``templates.cover_block`` / ``audience_language_directive`` — cover + audience
    tailoring for the case report.

Import those submodules directly; this package no longer exposes a builder.
"""
