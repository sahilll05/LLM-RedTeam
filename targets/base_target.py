"""
Abstract base class that every target adapter must implement.

A target adapter is a thin driver that knows how to:
  - send a prompt (plus optional system prompt and conversation history)
  - return the model's response as a plain string
  - normalize raw responses by stripping model-specific artifacts

All business logic (scoring, rate limiting, reporting) lives in the engine;
adapters only handle protocol translation.
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Optional


class BaseTarget(ABC):
    """Interface contract for all target adapters."""

    def __init__(self, config: dict):
        self.config        = config
        self.model         = config.get("model", "")
        self.system_prompt = config.get("system_prompt", "You are a helpful assistant.")
        self.timeout       = int(config.get("timeout", 60))
        self.log_requests  = config.get("log_requests", False)

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

    def normalize_response(self, raw_response: str) -> str:
        """
        Strip model-specific artifacts from the raw response before scoring.

        This base implementation handles common patterns seen across most LLMs:
          - <think>...</think> reasoning blocks (DeepSeek, Qwen, etc.)
          - <|thinking|>...</|thinking|> tags
          - Markdown code block wrappers around the entire response
          - Leading/trailing whitespace

        Subclasses should override to handle target-specific artifacts
        (e.g., tool_calls, citations, retrieved context markers).
        """
        if not raw_response:
            return ""

        text = raw_response

        # Remove <think>...</think> reasoning blocks (common in reasoning models)
        text = re.sub(
            r"<think>.*?</think>",
            "",
            text,
            flags=re.DOTALL | re.IGNORECASE,
        )

        # Remove <|thinking|>...</|thinking|> blocks (alternative format)
        text = re.sub(
            r"<\|thinking\|>.*?<\|/thinking\|>",
            "",
            text,
            flags=re.DOTALL | re.IGNORECASE,
        )

        # Remove <internal_thought>...</internal_thought> blocks
        text = re.sub(
            r"<internal_thought>.*?</internal_thought>",
            "",
            text,
            flags=re.DOTALL | re.IGNORECASE,
        )

        # Strip lone markdown code block wrapper if it wraps the entire response
        stripped = text.strip()
        if stripped.startswith("```") and stripped.endswith("```"):
            lines = stripped.split("\n")
            if len(lines) >= 3:
                # Remove first and last line (the ``` markers)
                text = "\n".join(lines[1:-1])

        return text.strip()

    def send_and_normalize(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        history: Optional[list[dict]] = None,
    ) -> str:
        """Send a prompt and normalize the response before returning."""
        raw = self.send(prompt, system_prompt, history)
        
        if self.log_requests:
            import json
            import os
            from pathlib import Path
            log_dir = Path("./reports")
            log_dir.mkdir(parents=True, exist_ok=True)
            log_file = log_dir / "requests_trace.jsonl"
            
            trace_entry = {
                "target": self.model,
                "system_prompt": system_prompt or self.system_prompt,
                "history": history,
                "prompt": prompt,
                "raw_response": raw
            }
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(trace_entry) + "\n")
                
        return self.normalize_response(raw)

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
