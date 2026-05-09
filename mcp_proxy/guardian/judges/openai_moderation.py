"""OpenAI Moderation API adapter.

Free tier with any OpenAI API key (``OPENAI_API_KEY``). Useful as a
zero-cost slow-path baseline for the audit-only mode rollout phase.

Reference: https://platform.openai.com/docs/guides/moderation
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any

import httpx

from mcp_proxy.guardian.judges import Judge, JudgeResult

_log = logging.getLogger("mcp_proxy.guardian.judges.openai_moderation")

_DEFAULT_URL = "https://api.openai.com/v1/moderations"
_DEFAULT_MODEL = "omni-moderation-latest"


class OpenAIModerationJudge(Judge):
    """Wraps OpenAI's ``/v1/moderations`` endpoint."""

    name = "openai_moderation"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str = _DEFAULT_MODEL,
        url: str = _DEFAULT_URL,
        http_client: httpx.AsyncClient | None = None,
        timeout_s: float = 5.0,
    ):
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY") or ""
        self._model = model
        self._url = url
        self._http = http_client
        self._owns_http = http_client is None
        self._timeout = timeout_s

    async def evaluate(
        self, payload: bytes, ctx: dict[str, Any],
    ) -> JudgeResult:
        if not self._api_key:
            return Judge.unavailable(
                judge=self.name, detail="key_missing: set OPENAI_API_KEY",
            )

        started = time.perf_counter()
        body = {
            "model": self._model,
            "input": payload.decode("utf-8", errors="replace"),
        }
        headers = {"Authorization": f"Bearer {self._api_key}"}
        try:
            client = self._http or httpx.AsyncClient(timeout=self._timeout)
            try:
                resp = await client.post(self._url, json=body, headers=headers)
            finally:
                if self._owns_http and client is not self._http:
                    await client.aclose()
        except httpx.HTTPError as exc:
            # Audit H-IO-2 — httpx exc text leaks upstream URL / TLS / DNS
            # detail; keep the ``http_error`` tag, drop the inner text.
            _log.warning("openai_moderation http error: %s", exc)
            return Judge.unavailable(
                judge=self.name, detail="http_error",
            )

        latency_ms = int((time.perf_counter() - started) * 1000)
        if resp.status_code != 200:
            return Judge.unavailable(
                judge=self.name,
                detail=f"upstream_status_{resp.status_code}: {resp.text[:240]}",
            )
        try:
            data = resp.json()
        except ValueError as exc:
            # Audit H-IO-2 — JSON decoder exc text quotes upstream body
            # bytes; keep the ``malformed_response`` tag, drop inner text.
            _log.warning("openai_moderation malformed response: %s", exc)
            return Judge.unavailable(
                judge=self.name, detail="malformed_response",
            )

        results = data.get("results") or []
        if not results:
            return Judge.unavailable(
                judge=self.name, detail="no_results_in_response",
            )
        first = results[0]
        flagged = bool(first.get("flagged"))
        categories = first.get("categories") or {}
        reasons: list[dict[str, Any]] = []
        for cat, hit in categories.items():
            if hit:
                reasons.append({"tool": f"openai_moderation.{cat}", "match": "flagged"})

        decision = "block" if flagged else "pass"
        return JudgeResult(
            decision=decision,
            judge=self.name,
            reasons=reasons,
            latency_ms=latency_ms,
        )
