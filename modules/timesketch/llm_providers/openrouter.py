# Copyright 2025 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""OpenRouter LLM provider for Timesketch.

OpenRouter (https://openrouter.ai) provides a unified API for accessing
multiple LLM providers (OpenAI, Anthropic, Google, Meta, etc.) through
a single OpenAI-compatible endpoint.

Installation:
    Copy this file to:
    timesketch/lib/llms/providers/contrib/openrouter.py

Configuration in timesketch.conf:
    LLM_PROVIDER_CONFIGS = {
        'default': {
            'openrouter': {
                'api_key': 'sk-or-v1-...',
                'model': 'anthropic/claude-3.5-sonnet',
            },
        },
        'nl2q': {
            'openrouter': {
                'api_key': 'sk-or-v1-...',
                'model': 'google/gemini-2.0-flash-001',
            },
        },
        'llm_summarization': {
            'openrouter': {
                'api_key': 'sk-or-v1-...',
                'model': 'anthropic/claude-3.5-sonnet',
                'max_output_tokens': 4096,
                'temperature': 0.3,
            },
        },
    }
"""

import json
import logging
from typing import Any, Optional, Union

import requests

from timesketch.lib.llms.providers import interface, manager

logger = logging.getLogger("timesketch.llm.provider.openrouter")

OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_TIMEOUT = 120


class OpenRouter(interface.LLMProvider):
    """OpenRouter provider for Timesketch.

    This provider uses the OpenRouter API (OpenAI-compatible) to generate text.
    It supports any model available on OpenRouter, including models from OpenAI,
    Anthropic, Google, Meta, Mistral, and others.

    Required config keys:
        api_key: OpenRouter API key (starts with sk-or-v1-...).
        model: Model identifier (e.g. 'anthropic/claude-3.5-sonnet').

    Optional config keys:
        timeout: Request timeout in seconds (default: 120).
        site_url: Your site URL for OpenRouter rankings/analytics.
        site_name: Your site name for OpenRouter rankings/analytics.
    """

    NAME = "openrouter"

    def __init__(self, config: dict, **kwargs: Any) -> None:
        """Initialize the OpenRouter provider.

        Args:
            config: A dictionary of provider-specific configuration options.
            **kwargs: Additional arguments passed to the base class.

        Raises:
            ValueError: If required configuration keys are missing.
        """
        super().__init__(config, **kwargs)
        self.api_key = self.config.get("api_key")
        self.model = self.config.get("model")
        self.timeout = self.config.get("timeout", DEFAULT_TIMEOUT)
        self.site_url = self.config.get("site_url", "")
        self.site_name = self.config.get("site_name", "Timesketch")

        if not self.api_key or not self.model:
            raise ValueError(
                "api_key and model are required for OpenRouter provider"
            )

    def generate(
        self, prompt: str, response_schema: Optional[dict] = None
    ) -> Union[dict, str]:
        """Generate text using the OpenRouter API.

        Args:
            prompt: The prompt to send to the model.
            response_schema: An optional JSON schema to define the expected
                response format.

        Returns:
            The generated text as a string, or a dict if response_schema
            is provided.

        Raises:
            ValueError: If the API response has an unexpected structure.
            requests.exceptions.RequestException: If the API request fails.
        """
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        if self.site_url:
            headers["HTTP-Referer"] = self.site_url
        if self.site_name:
            headers["X-Title"] = self.site_name

        data = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": self.config.get(
                "max_output_tokens", interface.DEFAULT_MAX_OUTPUT_TOKENS
            ),
            "temperature": self.config.get(
                "temperature", interface.DEFAULT_TEMPERATURE
            ),
            "top_p": self.config.get("top_p", interface.DEFAULT_TOP_P),
        }

        try:
            response = requests.post(
                OPENROUTER_API_URL,
                headers=headers,
                json=data,
                timeout=self.timeout,
            )
            response.raise_for_status()
            response_data = response.json()["choices"][0]["message"]["content"]
        except requests.exceptions.HTTPError as e:
            error_body = ""
            try:
                error_body = response.json()
            except (ValueError, AttributeError):
                error_body = response.text
            logger.error(
                "OpenRouter API error (HTTP %s): %s",
                response.status_code,
                error_body,
            )
            raise ValueError(
                f"OpenRouter API request failed (HTTP {response.status_code}): "
                f"{error_body}"
            ) from e
        except (KeyError, IndexError) as e:
            raise ValueError(
                f"Unexpected response structure from OpenRouter API: "
                f"{response.json()}"
            ) from e

        if isinstance(response_schema, dict):
            try:
                props = response_schema.get("properties")
                if props and isinstance(props, dict):
                    key = next(iter(props.keys()), "")
                    formatted_data = json.dumps({key: response_data})
                    return json.loads(formatted_data)
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"Error JSON parsing text: {formatted_data}: {error}"
                ) from error

        return response_data


manager.LLMManager.register_provider(OpenRouter)
