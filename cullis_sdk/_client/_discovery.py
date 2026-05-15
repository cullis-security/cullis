"""Discovery + pubkey-fetch support extracted from :mod:`cullis_sdk.client`.

Public symbols:

* :class:`PubkeyFetchError` — raised by the pubkey-fetch helpers (broker
  or egress) when a target agent's public key cannot be retrieved.
* :class:`_DiscoveryMixin` — mixin folded into ``CullisClient`` that
  exposes ``discover``, ``list_peers`` and the three pubkey lookup
  paths (broker, egress, and the fallback chain used by
  ``decrypt_oneshot``).

Movement only — no behavior change. The mixin assumes the host class
exposes ``_authed_request``, ``_egress_http`` and the ``_pubkey_cache``
attribute (initialised by ``CullisClient.__init__`` and every factory
classmethod, since the SDK factories bypass ``__init__``).
"""
from __future__ import annotations

import time

import httpx

from cullis_sdk.types import AgentInfo


_PUBKEY_CACHE_TTL = 300  # seconds


class PubkeyFetchError(RuntimeError):
    """Raised by pubkey-fetch helpers (broker or egress) when the
    target agent's public key cannot be retrieved.

    Distinct from generic HTTP/network errors so callers — notably
    ``decrypt_oneshot`` consumers — can discriminate "couldn't verify
    sender, must skip" from "decrypt itself failed". The Connector's
    inbox poller catches this specifically and logs at ERROR (security
    relevant: an unverifiable sender means the message is dropped).
    """


class _DiscoveryMixin:
    """Agent discovery + pubkey fetching on ``CullisClient``."""

    def discover(
        self,
        capabilities: list[str] | None = None,
        org_id: str | None = None,
        pattern: str | None = None,
        q: str | None = None,
    ) -> list[AgentInfo]:
        """Search for agents in the network.

        ADR-010 Phase 6a: reads from the ``/v1/federation/`` namespace,
        which is where the Court now serves cross-org discovery.
        """
        path = "/v1/federation/agents/search"
        params: list[tuple[str, str]] = []
        if capabilities:
            params.extend([("capability", c) for c in capabilities])
        if org_id:
            params.append(("org_id", org_id))
        if pattern:
            params.append(("pattern", pattern))
        if q:
            params.append(("q", q))
        if not params:
            params.append(("pattern", "*"))
        resp = self._authed_request("GET", path, params=params)
        resp.raise_for_status()
        return [AgentInfo.from_dict(a) for a in resp.json().get("agents", [])]

    def list_peers(
        self,
        q: str | None = None,
        limit: int = 50,
    ) -> list[AgentInfo]:
        """List peers reachable via the local Mastio's egress API.

        Hits ``GET /v1/egress/peers`` (API-key + DPoP authed — does NOT
        need a broker JWT, unlike :meth:`discover`). Returns intra-org
        agents from the Mastio's local registry plus any cross-org
        agents the federation cache currently holds.

        ``q`` is a server-side substring prefilter on ``agent_id`` /
        ``display_name``; the caller is expected to do the final
        ranking (e.g. with ``difflib``) since "best match" is UX-driven.
        """
        params: list[tuple[str, str]] = []
        if q:
            params.append(("q", q))
        if limit:
            params.append(("limit", str(limit)))
        resp = self._egress_http(
            "get",
            "/v1/egress/peers",
            params=params,
        )
        resp.raise_for_status()
        return [AgentInfo.from_dict(p) for p in resp.json().get("peers", [])]

    def get_agent_public_key(self, agent_id: str, force_refresh: bool = False) -> str:
        """Retrieve the agent's full X.509 cert PEM from the broker (TTL-cached).

        ADR-010 Phase 6a: reads from the ``/v1/federation/`` namespace.

        Issue #470 — the response carries both ``cert_pem`` (full X.509)
        and ``public_key_pem`` (bare SPKI). Prefer ``cert_pem`` since
        the H7 audit fix on the verify helpers rejects bare SPKI; fall
        back to ``public_key_pem`` only if the broker is older and
        doesn't populate the cert field, in which case the consumer
        loses the cert-to-identity binding step but the legacy contract
        keeps working.
        """
        if not force_refresh and agent_id in self._pubkey_cache:
            pubkey_pem, fetched_at = self._pubkey_cache[agent_id]
            if time.time() - fetched_at < _PUBKEY_CACHE_TTL:
                return pubkey_pem
        path = f"/v1/federation/agents/{agent_id}/public-key"
        resp = self._authed_request("GET", path)
        resp.raise_for_status()
        body = resp.json()
        pubkey_pem = body.get("cert_pem") or body["public_key_pem"]
        self._pubkey_cache[agent_id] = (pubkey_pem, time.time())
        return pubkey_pem

    def get_agent_public_key_via_egress(
        self, agent_id: str, force_refresh: bool = False,
    ) -> str:
        """Fetch the target agent's PEM cert through the local proxy's
        ``GET /v1/egress/agents/{id}/public-key`` endpoint.

        Egress-only variant — no broker fallback. Intended for callers
        that deliberately want to fail-fast when the proxy doesn't have
        the cert (e.g. device-code-enrolled Connectors that hold no
        broker JWT; falling back to the broker path would just
        surface a less-informative auth error). SDK consumers that
        want the broker fallback should leave ``decrypt_oneshot``'s
        ``pubkey_fetcher`` unset — the default chain covers both paths.

        Returns the PEM cert (not a bare key — the proxy hands back the
        full x509, the verify helpers in :mod:`cullis_sdk.crypto` accept
        either form). Reuses :attr:`_pubkey_cache` with the same TTL as
        the broker path so successive calls don't burn the per-agent
        egress rate-limit budget.

        Raises :class:`PubkeyFetchError` on any failure: 404/501 (route
        missing), 401/403 (auth broken), transport errors, or a 200
        response whose ``cert_pem`` is null/missing.
        """
        if not force_refresh and agent_id in self._pubkey_cache:
            pem, fetched_at = self._pubkey_cache[agent_id]
            if time.time() - fetched_at < _PUBKEY_CACHE_TTL:
                return pem
        path = f"/v1/egress/agents/{agent_id}/public-key"
        try:
            resp = self._egress_http("get", path)
            resp.raise_for_status()
            pem = resp.json().get("cert_pem")
        except PubkeyFetchError:
            raise
        except Exception as exc:
            raise PubkeyFetchError(
                f"GET {path} failed: {exc} ({type(exc).__name__})"
            ) from exc
        if not pem:
            raise PubkeyFetchError(
                f"proxy returned no cert_pem for {agent_id} "
                "(target may be cross-org with no broker bridge "
                "configured, or the agent does not exist)"
            )
        self._pubkey_cache[agent_id] = (pem, time.time())
        return pem

    def _fetch_pubkey_proxy_then_broker(self, agent_id: str) -> str:
        """Default pubkey lookup used by :meth:`decrypt_oneshot`.

        Order of operations:
          1. Ask the local Mastio's ``/v1/egress/agents/<id>/public-key``
             (auth'd via X-API-Key + DPoP — every SDK consumer has this).
          2. If the proxy returns 404 / 501 / cert_pem=null — conditions
             that mean "the proxy doesn't know this agent" rather than
             "the call itself failed" — fall back to the Court's
             ``/v1/federation/agents/<id>/public-key`` (requires a broker
             JWT).
          3. Genuine failures — 401 / 403 (auth broken), transport
             errors — propagate as :class:`PubkeyFetchError` WITHOUT a
             fallback: falling back would just mask a broken setup
             with a second, less-informative auth error.

        TTL-cached on :attr:`_pubkey_cache` so successive calls don't
        re-hit either path within the 300s window.
        """
        if agent_id in self._pubkey_cache:
            pem, fetched_at = self._pubkey_cache[agent_id]
            if time.time() - fetched_at < _PUBKEY_CACHE_TTL:
                return pem

        proxy_path = f"/v1/egress/agents/{agent_id}/public-key"
        should_fallback = False
        proxy_diag = ""
        try:
            resp = self._egress_http("get", proxy_path)
            if resp.status_code in (404, 501):
                should_fallback = True
                proxy_diag = f"proxy endpoint returned {resp.status_code}"
            else:
                resp.raise_for_status()
                pem = resp.json().get("cert_pem")
                if pem:
                    self._pubkey_cache[agent_id] = (pem, time.time())
                    return pem
                should_fallback = True
                proxy_diag = (
                    "proxy returned 200 but cert_pem was null "
                    "(cross-org target with no broker bridge configured "
                    "on the proxy — falling back to broker)"
                )
        except httpx.HTTPStatusError as exc:
            code = exc.response.status_code if exc.response is not None else 0
            if code in (404, 501):
                should_fallback = True
                proxy_diag = f"proxy endpoint returned {code}"
            else:
                raise PubkeyFetchError(
                    f"proxy {proxy_path} failed with HTTP {code} — "
                    "auth broken or proxy misconfigured, not retrying "
                    "via broker"
                ) from exc
        except Exception as exc:
            raise PubkeyFetchError(
                f"proxy {proxy_path} transport failure: "
                f"{exc} ({type(exc).__name__}) — not retrying via broker"
            ) from exc

        if not should_fallback:
            # Defensive: every branch above either returned, set the
            # flag, or raised. Reaching here is a programmer error.
            raise PubkeyFetchError(
                f"proxy lookup for {agent_id} ended in an unexpected state"
            )

        try:
            return self.get_agent_public_key(agent_id)
        except Exception as broker_exc:
            raise PubkeyFetchError(
                f"both pubkey lookups failed: {proxy_diag}; "
                f"broker fallback: {broker_exc} "
                f"({type(broker_exc).__name__})"
            ) from broker_exc
