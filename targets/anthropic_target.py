"""
Target adapter for Anthropic Claude models.

Supported models: claude-3-5-sonnet-20241022, claude-3-haiku-20240307, etc.

Requires ANTHROPIC_API_KEY environment variable or 'api_key' in config.
"""
from __future__ import annotations

import os
from typing import Optional

import httpx

from targets.base_target import BaseTarget

_API_URL         = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_VER   = "2023-06-01"


class AnthropicTarget(BaseTarget):
    """Sends prompts to Anthropic's Messages API."""

    def __init__(self, config: dict):
        super().__init__(config)
        self.api_key    = config.get("api_key") or os.environ.get("ANTHROPIC_API_KEY", "")
        self.max_tokens = int(config.get("max_tokens", 1024))

        if not self.api_key:
            raise ValueError(
                "Anthropic API key not found. "
                "Set 'api_key' in config.yaml or export ANTHROPIC_API_KEY=<your-key>"
            )

    def send(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        history: Optional[list[dict]] = None,
    ) -> str:
        sys_prompt = system_prompt or self.system_prompt
        messages: list[dict] = []

        if history:
            messages.extend(history)
        messages.append({"role": "user", "content": prompt})

        # Anthropic puts system prompt at the top-level, not as a message
        payload: dict = {
            "model":      self.model,
            "max_tokens": self.max_tokens,
            "messages":   messages,
        }
        if sys_prompt:
            payload["system"] = sys_prompt

        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(
                _API_URL,
                headers={
                    "x-api-key":         self.api_key,
                    "anthropic-version": _ANTHROPIC_VER,
                    "Content-Type":      "application/json",
                },
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()["content"][0]["text"]

    def health_check(self) -> bool:
        """Send a minimal request to verify credentials."""
        try:
            self.send("Hi", system_prompt="Respond with one word only.")
            return True
        except Exception:
            return False
