"""
Abstract base class that every target adapter must implement.

A target adapter is a thin driver that knows how to:
  - send a prompt (plus optional system prompt and conversation history)
  - return the model's response as a plain string

All business logic (scoring, rate limiting, reporting) lives in the engine;
adapters only handle protocol translation.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional


class BaseTarget(ABC):
    """Interface contract for all target adapters."""

    def __init__(self, config: dict):
        self.config        = config
        self.model         = config.get("model", "")
        self.system_prompt = config.get("system_prompt", "You are a helpful assistant.")
        self.timeout       = int(config.get("timeout", 60))

    @abstractmethod
    def send(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        history: Optional[list[dict]] = None,
    ) -> str:
        """
        Send a prompt to the target and return the response text.

        Args:
            prompt:        The user-turn message to send.
            system_prompt: Override the default system prompt for this request.
            history:       Prior conversation turns as a list of
                           {"role": "user"|"assistant", "content": str} dicts.
        Returns:
            The model's response as a plain string.
        Raises:
            httpx.HTTPStatusError  if the API returns a non-2xx status.
            httpx.ConnectError     if the target is unreachable.
        """
        ...

    def health_check(self) -> bool:
        """
        Verify the target is reachable and responding.
        Subclasses should override with a faster, non-payload check where possible.
        """
        try:
            response = self.send("Hello")
            return bool(response and response.strip())
        except Exception:
            return False
