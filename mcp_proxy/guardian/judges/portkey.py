"""Portkey Guardrails adapter.

Portkey runs an AI gateway product (which we already integrate as an
egress backend in ``mcp_proxy.egress.ai_gateway``) and a Guardrails
product. Both share the same dashboard / API key but live on different
endpoints. This adapter targets the Guardrails endpoint specifically.

Reference: https://portkey.ai/docs/product/guardrails

Phase 1 ships the call shape; dogfood is gated on
``PORTKEY_API_KEY`` + a chosen guardrail config id
(``PORTKEY_GUARDRAIL_ID``).
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any

import httpx

from mcp_proxy.guardian.judges import Judge, JudgeResult

_log = logging.getLogger("mcp_proxy.guardian.judges.portkey")

_DEFAULT_URL = "https://api.portkey.ai/v1/guardrails/check"


class PortkeyJudge(Judge):
    """Wraps the Portkey Guardrails ``/v1/guardrails/check`` endpoint."""

    name = "portkey"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        guardrail_id: str | None = None,
        url: str = _DEFAULT_URL,
        http_client: httpx.AsyncClient | None = None,
        timeout_s: float = 5.0,
    ):
        self._api_key = api_key or os.environ.get("PORTKEY_API_KEY") or ""
        self._guardrail_id = (
            guardrail_id or os.environ.get("PORTKEY_GUARDRAIL_ID") or ""
        )
        self._url = url
        self._http = http_client
        self._owns_http = http_client is None
        self._timeout = timeout_s

    async def evaluate(
        self, payload: bytes, ctx: dict[str, Any],
    ) -> JudgeResult:
        if not self._api_key:
            return Judge.unavailable(
                judge=self.name, detail="key_missing: set PORTKEY_API_KEY",
            )
        if not self._guardrail_id:
            return Judge.unavailable(
                judge=self.name,
                detail="config_missing: set PORTKEY_GUARDRAIL_ID",
            )

        started = time.perf_counter()
        body = {
            "guardrail_id": self._guardrail_id,
            "input": payload.decode("utf-8", errors="replace"),
        }
        headers = {
            "x-portkey-api-key": self._api_key,
            "Content-Type": "application/json",
        }
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
            _log.warning("portkey http error: %s", exc)
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
            _log.warning("portkey malformed response: %s", exc)
            return Judge.unavailable(
                judge=self.name, detail="malformed_response",
            )

        # Portkey shape: ``verdict: "pass" | "fail"`` + per-check details.
        verdict = (data.get("verdict") or "").lower()
        decision = "pass" if verdict == "pass" else "block"
        checks = data.get("checks") or []
        reasons: list[dict[str, Any]] = []
        for chk in checks:
            if chk.get("verdict", "").lower() != "pass":
                reasons.append({
                    "tool": f"portkey.{chk.get('id', 'unknown')}",
                    "match": str(chk.get("explanation", ""))[:240],
                })
        return JudgeResult(
            decision=decision,
            judge=self.name,
            reasons=reasons,
            latency_ms=latency_ms,
        )
