#!/usr/bin/env python3
"""
Agentic Constants - Centralized configuration values
"""

# LLM Configuration
TRUNCATE_TOKEN_LIMIT = 100000  # ~25K tokens, max data size before truncation
MAX_LLM_TOKENS = 16384  # Max response tokens for online LLMs (increased for detailed reports)
OLLAMA_CONTEXT_SIZE = 65536  # Context window for Ollama (increased for detailed reports)
OLLAMA_TIMEOUT_SECONDS = 600  # Request timeout for Ollama (10 min for detailed reports)

# Collection Configuration
COLLECTION_POLL_INTERVAL = 30  # Seconds between polling for results
ROWS_PER_QUERY = 5000  # Max rows per VQL query

# Log Prefixes
LOG_PREFIX_VELOCIRAPTOR = "[Velociraptor]"
LOG_PREFIX_LLM = "[LLM]"
LOG_PREFIX_PIPELINE = "[Pipeline]"
LOG_PREFIX_TIME_FILTER = "[TIME-FILTER]"
LOG_PREFIX_SKILLS = "[Skills]"

# Skills (DFIR domain knowledge injected per-artifact into the system prompt).
# Selected from upstream Anthropic Cybersecurity Skills (Apache-2.0). Each skill
# is a markdown body of ~2-5K tokens; we load top-K per artifact analysis.
SKILL_BODY_HARD_CAP = 8000     # tokens — reject skills above this on load
SKILL_BODY_SOFT_CAP = 5000     # tokens — warn (still loaded) above this
SKILL_DEFAULT_TOP_K = 1        # how many skills to inject per artifact
SKILL_MIN_SCORE = 3            # minimum selector score; below this we inject
                               # nothing (better to fall back to the base
                               # prompt than ship a tangentially-relevant
                               # skill — single-keyword matches score 1-2
                               # and are noise; meaningful matches cross 3).
