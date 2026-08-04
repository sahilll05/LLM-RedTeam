"""
Target adapter for OpenAI-compatible APIs.

Works with:
  - OpenAI (GPT-4o, GPT-4o-mini, GPT-3.5-turbo, ...)
  - Azure OpenAI (set base_url to your Azure endpoint)
  - Local OpenAI-compatible servers (LM Studio, vLLM, etc.)

Requires OPENAI_API_KEY environment variable or 'api_key' in config.
"""
from __future__ import annotations

import os
from typing import Optional

import httpx

from targets.base_target import BaseTarget

_DEFAULT_BASE = "https://api.openai.com"


class OpenAITarget(BaseTarget):
    """Sends prompts to the OpenAI Chat Completions API (or any compatible endpoint)."""

    def __init__(self, config: dict):
        super().__init__(config)
        self.api_key     = config.get("api_key") or os.environ.get("OPENAI_API_KEY", "")
        self.base_url    = config.get("base_url", _DEFAULT_BASE).rstrip("/")
        self.temperature = float(config.get("temperature", 1.0))
        self.max_tokens  = config.get("max_tokens")  # None = model default

        if not self.api_key:
            raise ValueError(
                "OpenAI API key not found. "
                "Set 'api_key' in config.yaml or export OPENAI_API_KEY=<your-key>"
            )

    def send(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        history: Optional[list[dict]] = None,
    ) -> str:
        sys_prompt = system_prompt or self.system_prompt
        messages: list[dict] = []

        if sys_prompt:
            messages.append({"role": "system", "content": sys_prompt})
        if history:
            messages.extend(history)
        messages.append({"role": "user", "content": prompt})

        body: dict = {
            "model":       self.model,
            "messages":    messages,
            "temperature": self.temperature,
        }
        if self.max_tokens:
            body["max_tokens"] = self.max_tokens

        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(
                f"{self.base_url}/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type":  "application/json",
                },
                json=body,
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]

    def health_check(self) -> bool:
        """List available models to confirm the API key and endpoint are valid."""
        try:
            with httpx.Client(timeout=10) as client:
                resp = client.get(
                    f"{self.base_url}/v1/models",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                )
                return resp.status_code == 200
        except Exception:
            return False
