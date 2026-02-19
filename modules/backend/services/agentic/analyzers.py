#!/usr/bin/env python3
"""
Agentic Analyzers - LLM analysis functions for forensic data
"""

import json
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed


def analyze_single_artifact(artifact, rows, llm_config, anonymizer=None):
    """Analyze a single artifact with LLM. Returns (artifact, summary, error) tuple.
    If anonymizer is provided, data is masked before sending to LLM."""
    # Apply anonymization if enabled
    if anonymizer:
        rows = anonymizer.mask_data(rows)

    # Truncate data to fit context window
    data_str = json.dumps(rows, indent=2, default=str)
    if len(data_str) > 100000:  # ~25K tokens
        data_str = data_str[:100000] + "\n... (truncated)"

    system_prompt = """You are a forensic security analyst performing incident response triage. Analyze the provided Velociraptor artifact data thoroughly.

For EACH artifact, you MUST provide:
1. **Summary**: What this data shows (1-2 sentences)
2. **Notable Findings**: List ALL interesting items, categorized by severity:
   - CRITICAL/HIGH: Active threats, malware, unauthorized access, credential theft
   - MEDIUM: Suspicious activity, renamed binaries, unusual persistence, recon commands
   - LOW/INFO: Baseline context (user accounts, installed software, network connections)
3. **IOCs Found**: Any IPs, domains, hashes, suspicious file paths, registry keys
4. **MITRE ATT&CK**: Map findings to technique IDs where applicable

IMPORTANT: Do NOT dismiss data as "no significant findings" unless the artifact is truly empty.
Even benign-looking data provides forensic context. Report what you see - renamed binaries,
downloaded tools, PowerShell history, RDP sessions, DNS lookups, persistence entries,
unusual processes, and service installations are ALL worth reporting."""

    user_prompt = f"""Analyze these forensic results from artifact: {artifact}

Data ({len(rows)} rows):
{data_str}

Provide a detailed triage summary:"""

    try:
        summary = call_llm(user_prompt, system_prompt, llm_config)
        return (artifact, summary, None)
    except Exception as e:
        return (artifact, f"Analysis failed: {str(e)}", str(e))


def analyze_artifacts(run_id, all_results, llm_config, anonymizer=None, log_func=None):
    """Run LLM analysis on each artifact's results using parallel execution"""
    from services.workflow_service import add_log_to_run

    def log(msg, level="info"):
        if log_func:
            log_func(msg, level)
        add_log_to_run(run_id, msg, level)

    summaries = {}
    artifacts_list = list(all_results.keys())

    if not artifacts_list:
        return summaries

    # Get max concurrent requests from config (default: 5)
    max_concurrent = llm_config.get('agentic', {}).get('max_concurrent_requests', 5)
    log(f"[LLM] Starting parallel analysis with {max_concurrent} concurrent requests")

    # Submit all analysis tasks to thread pool
    futures = {}
    with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
        for artifact in artifacts_list:
            rows = all_results[artifact]
            log(f"[LLM] Queued {artifact} ({len(rows)} rows) for analysis")
            future = executor.submit(analyze_single_artifact, artifact, rows, llm_config, anonymizer)
            futures[future] = artifact

        # Collect results as they complete
        completed = 0
        for future in as_completed(futures):
            artifact, summary, error = future.result()
            summaries[artifact] = summary
            completed += 1

            if error:
                log(f"[LLM] Error for {artifact}: {error}", "warning")
            else:
                log(f"[LLM] Analysis complete for {artifact} ({completed}/{len(artifacts_list)})")

    return summaries


def call_llm(prompt, system_prompt, config):
    """Call the configured LLM provider"""
    agentic_config = config.get('agentic', {})
    mode = agentic_config.get('llm_mode', 'offline')

    if mode == 'online':
        return _call_llm_online(prompt, system_prompt, agentic_config.get('online_llm', {}))
    else:
        return _call_llm_offline(prompt, system_prompt, agentic_config.get('offline_llm', {}))


def _call_llm_online(prompt, system_prompt, provider_config):
    """Call Claude or other online LLM"""
    provider = provider_config.get('provider', 'claude')
    api_key = provider_config.get('api_key', '')
    model = provider_config.get('model', 'claude-sonnet-4-20250514')

    if not api_key:
        raise ValueError("Online LLM API key not configured. Set it in Settings.")

    if provider == 'claude':
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model=model,
            max_tokens=4096,
            system=system_prompt,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.content[0].text
    elif provider == 'openai':
        import openai
        client = openai.OpenAI(api_key=api_key)
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=4096,
            temperature=0.1
        )
        return response.choices[0].message.content
    else:
        raise ValueError(f"Unsupported online provider: {provider}")


def _call_llm_offline(prompt, system_prompt, provider_config):
    """Call Ollama or other local LLM"""
    provider = provider_config.get('provider', 'ollama')
    model = provider_config.get('model', 'llama3.3:70b')
    url = provider_config.get('url', 'http://localhost:11434')

    if provider == 'ollama':
        full_prompt = f"{system_prompt}\n\n{prompt}"
        response = requests.post(
            f"{url}/api/generate",
            json={
                "model": model,
                "prompt": full_prompt,
                "stream": False,
                "options": {
                    "num_ctx": 32768
                }
            },
            timeout=300
        )
        response.raise_for_status()
        return response.json().get('response', '')
    else:
        raise ValueError(f"Unsupported offline provider: {provider}")
