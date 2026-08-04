"""
Target adapter for locally running Ollama models.

Supports any model available via `ollama pull`, e.g.:
    llama3, mistral, gemma2, phi3, llama3:8b, ...

No API key required. Ollama must be running: https://ollama.com
"""
from __future__ import annotations

from typing import Optional

import httpx

from targets.base_target import BaseTarget


class OllamaTarget(BaseTarget):
    """Sends prompts to a locally running Ollama instance via its REST API."""

    def __init__(self, config: dict):
        super().__init__(config)
        self.base_url = config.get("base_url", "http://localhost:11434").rstrip("/")

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

        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(
                f"{self.base_url}/api/chat",
                json={
                    "model":    self.model,
                    "messages": messages,
                    "stream":   False,
                },
            )
            resp.raise_for_status()
            return resp.json()["message"]["content"]

    def health_check(self) -> bool:
        """Check Ollama is running and the configured model is available."""
        try:
            with httpx.Client(timeout=10) as client:
                resp = client.get(f"{self.base_url}/api/tags")
                if resp.status_code != 200:
                    return False
                available = [m["name"] for m in resp.json().get("models", [])]
                # Accept partial match (e.g. "llama3" matches "llama3:latest")
                return any(self.model in name for name in available) or not available
        except Exception:
            return False

    def list_models(self) -> list[str]:
        """Return names of locally available Ollama models."""
        with httpx.Client(timeout=10) as client:
            resp = client.get(f"{self.base_url}/api/tags")
            resp.raise_for_status()
            return [m["name"] for m in resp.json().get("models", [])]
