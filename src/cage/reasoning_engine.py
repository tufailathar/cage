from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

# Load secrets (from .env file)
_SECRETS = Path(__file__).resolve().parents[2] / "secrets" / ".env"
if _SECRETS.exists():
    load_dotenv(_SECRETS)
else:
    load_dotenv()


# ═════════════════════════════════════════════════════════════════
# Response validation
# ═════════════════════════════════════════════════════════════════
REQUIRED_KEYS = frozenset({"thought", "phase", "tool_name", "arguments"})


def _validate(raw: dict) -> dict:
    missing = REQUIRED_KEYS - set(raw.keys())
    if missing:
        raise ValueError(f"Model response missing keys: {missing}")
    if not isinstance(raw.get("arguments"), dict):
        raw["arguments"] = {}
    return {
        "thought":   str(raw["thought"]),
        "phase":     str(raw.get("phase", "recon")).lower().strip(),
        "tool_name": str(raw["tool_name"]).lower().strip(),
        "arguments": dict(raw["arguments"]),
    }


# ═════════════════════════════════════════════════════════════════
# Abstract base (Kept for typing/architecture cleanliness)
# ═════════════════════════════════════════════════════════════════
class BaseLLM(ABC):
    @abstractmethod
    def get_next_action(self, full_prompt: str) -> dict[str, Any]: ...

    @property
    @abstractmethod
    def last_token_usage(self) -> dict: ...


# ═════════════════════════════════════════════════════════════════
# Meta Muse Spark Open (via Baseten)
# ═════════════════════════════════════════════════════════════════
class MetaMuseSparkLLM(BaseLLM):
    """
    Meta Muse Spark Open provider — OpenAI-compatible API via Baseten.
    """

    _SYSTEM_SUFFIX = (
        "\n\nCRITICAL: Your response MUST be a single valid JSON object. "
        "No markdown, no code fences, no prose outside the JSON."
    )

    MODEL = "meta-models/muse-spark-open"
    BASE_URL = "https://inference.baseten.co/v1"

    def __init__(
        self,
        max_tokens: int = 4096,
        temperature: float = 0.15,
        timeout: int = 120,
    ):
        try:
            from openai import OpenAI
        except ImportError:
            raise ImportError("Install openai: pip install openai")

        api_key = os.getenv("BASETEN_API_KEY", "").strip()
        if not api_key:
            raise ValueError(
                "No BASETEN_API_KEY in secrets/.env. "
                "Get one at https://baseten.co"
            )

        self._client = OpenAI(
            api_key=api_key,
            base_url=self.BASE_URL,
            timeout=timeout,
        )
        self._max_tokens = max_tokens
        self._temperature = temperature
        self._last_usage: dict = {"tokens_in": 0, "tokens_out": 0}

    @property
    def last_token_usage(self) -> dict:
        return self._last_usage

    def get_next_action(self, full_prompt: str) -> dict[str, Any]:
        try:
            resp = self._client.chat.completions.create(
                model=self.MODEL,
                messages=[
                    {"role": "system", "content": full_prompt + self._SYSTEM_SUFFIX},
                    {"role": "user", "content": "Output your next action as JSON:"},
                ],
                max_tokens=self._max_tokens,
                temperature=self._temperature,
                response_format={"type": "json_object"},
                stream=False,
            )
        except Exception as e:
            raise RuntimeError(
                f"Baseten/Muse Spark call failed: {type(e).__name__}: {e}"
            )

        # Track usage
        usage = getattr(resp, "usage", None)
        if usage:
            self._last_usage = {
                "tokens_in": getattr(usage, "prompt_tokens", 0) or 0,
                "tokens_out": getattr(usage, "completion_tokens", 0) or 0,
            }

        raw = ""
        if resp.choices and resp.choices[0].message:
            raw = resp.choices[0].message.content or ""

        raw = raw.strip()

        # Strip markdown fences if the model emitted them
        if raw.startswith("```"):
            lines = raw.split("\n")
            raw = "\n".join(
                l for l in lines if not l.strip().startswith("```")
            ).strip()
            if raw.startswith("json"):
                raw = raw[4:].lstrip()

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ValueError(f"Muse Spark non-JSON: {e}; raw={raw[:300]}")

        return _validate(data)



def get_llm() -> BaseLLM:
    """Return the Meta Muse Spark Open model."""
    return MetaMuseSparkLLM()
