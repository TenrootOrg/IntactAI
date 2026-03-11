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
