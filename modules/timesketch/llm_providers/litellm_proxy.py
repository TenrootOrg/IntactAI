# Copyright 2025 Google Inc. All rights reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# LiteLLM proxy provider for Timesketch.
# See https://docs.litellm.ai for the proxy server.
import json
import logging

import requests

from timesketch.lib.llms.providers import interface
from timesketch.lib.llms.providers import manager

logger = logging.getLogger("timesketch.llm.provider.litellm_proxy")

CHAT_COMPLETIONS_PATH = "/chat/completions"
DEFAULT_TIMEOUT = 120


class LiteLLM(interface.LLMProvider):
    NAME = "litellm_proxy"

    def __init__(self, config, **kwargs):
        super().__init__(config, **kwargs)
        self.server_url = (self.config.get("server_url") or "").rstrip("/")
        self.model = self.config.get("model")
        self.api_key = self.config.get("api_key")
        self.timeout = self.config.get("timeout", DEFAULT_TIMEOUT)
        self.extra_headers = self.config.get("extra_headers") or {}

        if not self.server_url:
            raise ValueError(
                "LiteLLM provider requires a server_url in its configuration."
            )
        if not self.model:
            raise ValueError(
                "LiteLLM provider requires a model in its configuration."
            )

    def generate(self, prompt, response_schema=None):
        url = self.server_url + CHAT_COMPLETIONS_PATH
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = "Bearer " + self.api_key
        if isinstance(self.extra_headers, dict):
            headers.update(self.extra_headers)

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

        if isinstance(response_schema, dict):
            data["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": response_schema.get("title", "response"),
                    "schema": response_schema,
                    "strict": True,
                },
            }

        response = None
        try:
            response = requests.post(
                url,
                headers=headers,
                json=data,
                timeout=self.timeout,
            )
            response.raise_for_status()
            response_data = response.json()["choices"][0]["message"]["content"]
        except requests.exceptions.Timeout as error:
            raise ValueError(
                "LiteLLM request timed out after %ss: %s" % (self.timeout, error)
            ) from error
        except requests.exceptions.HTTPError as error:
            body = ""
            try:
                body = response.json() if response is not None else ""
            except (ValueError, AttributeError):
                body = response.text if response is not None else ""
            status = response.status_code if response is not None else "unknown"
            logger.error("LiteLLM API error (HTTP %s): %s", status, body)
            raise ValueError(
                "LiteLLM API request failed (HTTP %s): %s" % (status, body)
            ) from error
        except requests.exceptions.RequestException as error:
            raise ValueError(
                "Error making request to LiteLLM proxy at %s: %s" % (url, error)
            ) from error
        except (KeyError, IndexError, ValueError) as error:
            body = response.text if response is not None else ""
            raise ValueError(
                "Unexpected response structure from LiteLLM proxy: %s" % body
            ) from error

        if isinstance(response_schema, dict):
            try:
                return json.loads(response_data)
            except json.JSONDecodeError:
                pass
            try:
                props = response_schema.get("properties")
                if props and isinstance(props, dict):
                    key = next(iter(props.keys()), "")
                    return json.loads(json.dumps({key: response_data}))
            except json.JSONDecodeError as error:
                raise ValueError(
                    "Error JSON parsing text: %s: %s" % (response_data, error)
                ) from error

        return response_data


manager.LLMManager.register_provider(LiteLLM)
