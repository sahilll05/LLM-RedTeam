"""
Generic HTTP target adapter.

Useful for testing any chatbot that exposes an HTTP endpoint,
without needing a dedicated adapter (customer support bots,
internal company chatbots, third-party AI wrappers, etc.).

Config options (in config.yaml):
  type:             http
  endpoint:         http://localhost:8080/chat    # required
  method:           POST                          # GET | POST (default: POST)
  headers:
    Content-Type:   application/json
    Authorization:  Bearer <token>
  request_template: '{"message": "$prompt", "context": "$system_prompt"}'
      # Python string.Template format — $prompt and $system_prompt are substituted.
      # If omitted, defaults to OpenAI-compatible chat format.
  response_field:   reply
      # Dot-separated path into the JSON response to extract the text.
      # e.g. "choices.0.message.content" for OpenAI-compatible APIs.
      # e.g. "reply" for {"reply": "..."} shaped responses.
"""
from __future__ import annotations

import json
from string import Template
from typing import Optional

import httpx

from targets.base_target import BaseTarget


class HTTPTarget(BaseTarget):
    """Generic HTTP adapter for arbitrary chatbot endpoints."""

    def __init__(self, config: dict):
        super().__init__(config)
        self.endpoint         = config.get("endpoint")
        self.method           = config.get("method", "POST").upper()
        self.headers          = config.get("headers", {"Content-Type": "application/json"})
        self.request_template = config.get("request_template")
        self.response_field   = config.get("response_field", "response")

        if not self.endpoint:
            raise ValueError(
                "HTTP target requires 'endpoint' in config.yaml, "
                "e.g.  endpoint: http://localhost:8080/chat"
            )

    def send(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        history: Optional[list[dict]] = None,
    ) -> str:
        sys_prompt = system_prompt or self.system_prompt

        if self.request_template:
            body = self._render_template(prompt, sys_prompt)
        else:
            # Default: OpenAI-compatible chat completions body
            messages: list[dict] = []
            if sys_prompt:
                messages.append({"role": "system", "content": sys_prompt})
            if history:
                messages.extend(history)
            messages.append({"role": "user", "content": prompt})
            body = {"messages": messages}

        with httpx.Client(timeout=self.timeout) as client:
            if self.method == "POST":
                resp = client.post(
                    self.endpoint,
                    headers=self.headers,
                    json=body,
                )
            elif self.method == "GET":
                resp = client.get(
                    self.endpoint,
                    headers=self.headers,
                    params={"prompt": prompt, "system": sys_prompt},
                )
            else:
                raise ValueError(f"Unsupported HTTP method: {self.method}")

            resp.raise_for_status()
            return self._extract(resp.json())

    def _render_template(self, prompt: str, system_prompt: str) -> dict:
        """Substitute $prompt / $system_prompt into the request template and parse."""
        # Escape the values for safe JSON embedding
        tmpl = Template(self.request_template)
        rendered = tmpl.safe_substitute(
            prompt=prompt.replace('"', '\\"').replace("\n", "\\n"),
            system_prompt=system_prompt.replace('"', '\\"').replace("\n", "\\n"),
        )
        return json.loads(rendered)

    def _extract(self, data: object) -> str:
        """Navigate a dot-separated field path through the response JSON."""
        current = data
        for part in self.response_field.split("."):
            if isinstance(current, list):
                current = current[int(part)]
            elif isinstance(current, dict):
                current = current[part]
            else:
                break
        return str(current)
