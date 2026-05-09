"""Llama Guard adapter (Meta) — hosted via litellm-routed providers.

Llama Guard 3 / 4 ships as a model on Replicate, Together, Anyscale,
Fireworks, and other LiteLLM-compatible providers. The adapter reuses
``litellm.acompletion`` (already on the proxy's dependency list) so we
don't duplicate provider plumbing.

Phase 1 ships the adapter callable; dogfood is gated on whichever
LiteLLM-compatible key the operator picks (``REPLICATE_API_KEY``,
``TOGETHER_API_KEY``, …) plus a model id like
``replicate/meta/meta-llama-guard-2-8b``.

Reference: https://huggingface.co/meta-llama/Meta-Llama-Guard-2-8B
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any

from mcp_proxy.guardian.judges import Judge, JudgeResult

_log = logging.getLogger("mcp_proxy.guardian.judges.llama_guard")

_DEFAULT_MODEL = "replicate/meta/meta-llama-guard-2-8b"


class LlamaGuardJudge(Judge):
    """Wraps Llama Guard via LiteLLM-routed providers."""

    name = "llama_guard"

    def __init__(
        self,
        *,
        model: str | None = None,
        api_key_env: str = "REPLICATE_API_KEY",
        timeout_s: float = 10.0,
    ):
        self._model = model or os.environ.get("LLAMA_GUARD_MODEL") or _DEFAULT_MODEL
        self._api_key_env = api_key_env
        self._timeout = timeout_s

    async def evaluate(
        self, payload: bytes, ctx: dict[str, Any],
    ) -> JudgeResult:
        api_key = os.environ.get(self._api_key_env) or ""
        if not api_key:
            return Judge.unavailable(
                judge=self.name,
                detail=f"key_missing: set {self._api_key_env}",
            )

        try:
            from litellm import acompletion
        except ImportError as exc:
            # Audit H-IO-2 — ImportError text echoes module path / version
            # internals; keep the stable tag, drop the inner text.
            _log.warning("llama_guard litellm import failed: %s", exc)
            return Judge.unavailable(
                judge=self.name,
                detail="litellm_not_installed",
            )

        text = payload.decode("utf-8", errors="replace")
        # Llama Guard expects a chat-shape message and replies with one
        # of: "safe" or "unsafe\n<category>".
        prompt = (
            "Evaluate the following message for safety. Reply with "
            "'safe' or 'unsafe\\n<category>' only.\n\n" + text
        )

        started = time.perf_counter()
        try:
            response = await acompletion(
                model=self._model,
                messages=[{"role": "user", "content": prompt}],
                api_key=api_key,
                timeout=self._timeout,
            )
        except Exception as exc:
            # Audit H-IO-2 — upstream exc text leaks provider URL / API
            # error body / TLS detail; keep the tag, drop inner text.
            _log.warning("llama_guard upstream error: %s", exc)
            return Judge.unavailable(
                judge=self.name, detail="upstream_error",
            )

        latency_ms = int((time.perf_counter() - started) * 1000)
        try:
            content = response.choices[0].message.content or ""
        except Exception as exc:
            # Audit H-IO-2 — exc text from response decode quotes upstream
            # body bytes; keep the tag, drop inner text.
            _log.warning("llama_guard malformed response: %s", exc)
            return Judge.unavailable(
                judge=self.name, detail="malformed_response",
            )

        verdict = content.strip().lower()
        is_unsafe = verdict.startswith("unsafe")
        category: str | None = None
        if is_unsafe and "\n" in verdict:
            category = verdict.split("\n", 1)[1].strip()

        decision = "block" if is_unsafe else "pass"
        reasons: list[dict[str, Any]] = []
        if is_unsafe:
            reasons.append({
                "tool": f"llama_guard.{category or 'unspecified'}",
                "match": content[:240],
            })
        return JudgeResult(
            decision=decision,
            judge=self.name,
            reasons=reasons,
            latency_ms=latency_ms,
        )
