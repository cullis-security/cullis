"""Lakera Guard adapter.

Lakera is a guardrails specialist (no gateway product) — natural
non-overlapping integration partner. Their public API is OpenAI-shape
and accepts a payload + a list of detector flags. We default to
``prompt_injection`` + ``pii``; operators extend via ``detectors``.

Phase 1 ships the adapter callable but, by design, dogfood is gated on
``LAKERA_API_KEY``. Without the key the adapter returns ``unavailable``
with ``key_missing`` so the dogfood script and the audit timeline can
distinguish "not configured" from "rejected by Lakera".

Reference: https://platform.lakera.ai/docs/api/guard
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any

import httpx

from mcp_proxy.guardian.judges import Judge, JudgeResult

_log = logging.getLogger("mcp_proxy.guardian.judges.lakera")

_DEFAULT_URL = "https://api.lakera.ai/v2/guard"


class LakeraJudge(Judge):
    """Wraps the Lakera Guard endpoint."""

    name = "lakera"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        url: str = _DEFAULT_URL,
        detectors: list[str] | None = None,
        http_client: httpx.AsyncClient | None = None,
        timeout_s: float = 5.0,
    ):
        self._api_key = api_key or os.environ.get("LAKERA_API_KEY") or ""
        self._url = url
        self._detectors = detectors or ["prompt_injection", "pii"]
        self._http = http_client
        self._owns_http = http_client is None
        self._timeout = timeout_s

    async def evaluate(
        self, payload: bytes, ctx: dict[str, Any],
    ) -> JudgeResult:
        if not self._api_key:
            return Judge.unavailable(
                judge=self.name,
                detail="key_missing: set LAKERA_API_KEY",
            )

        started = time.perf_counter()
        body = {
            "messages": [
                {"role": "user", "content": payload.decode("utf-8", errors="replace")},
            ],
            "breakdown": True,
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
            _log.warning("lakera http error: %s", exc)
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
            # bytes; keep the tag, drop inner text.
            _log.warning("lakera malformed response: %s", exc)
            return Judge.unavailable(
                judge=self.name, detail="malformed_response",
            )

        # Lakera v2 shape: ``flagged: bool`` + ``breakdown`` per detector.
        flagged = bool(data.get("flagged"))
        breakdown = data.get("breakdown") or []
        reasons: list[dict[str, Any]] = []
        for entry in breakdown:
            if entry.get("detected"):
                reasons.append({
                    "tool": f"lakera.{entry.get('detector_type', 'unknown')}",
                    "match": entry.get("result", "")[:240],
                })

        decision = "block" if flagged else "pass"
        return JudgeResult(
            decision=decision,
            judge=self.name,
            reasons=reasons,
            latency_ms=latency_ms,
        )
