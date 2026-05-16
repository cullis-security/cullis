"""Microsoft Graph client for Intune managed-device inventory.

Implements the minimum surface F2 needs:

* OAuth2 client_credentials grant against ``login.microsoftonline.com``
  with a small in-memory token cache (50 minute TTL; Microsoft mints
  tokens at 60 min, we refresh 10 min early to avoid the cliff).
* ``managedDevices/delta`` delta-paging fetcher. First call has no
  ``delta_link`` and returns the full inventory; subsequent calls
  pass the ``@odata.deltaLink`` from the prior response and only
  return changed rows.

What this module is NOT:

* Not a general Graph SDK. Only the two endpoints F2 needs are
  implemented. Resist the urge to grow it into one — every additional
  scope expands the security surface customers have to approve.
* Not the polling loop. That lives in :mod:`mcp_proxy.mdm.poller`
  so the network/IO part stays independently testable.

Credentials are read from :class:`mcp_proxy.config.ProxySettings`
(``mdm_intune_tenant_id`` etc.) and passed in explicitly by the
caller. The client never reads env vars itself — keeps unit tests
hermetic.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

import httpx

_log = logging.getLogger("mcp_proxy.mdm.intune")

# Endpoints
_LOGIN_HOST = "https://login.microsoftonline.com"
_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
_GRAPH_SCOPE = "https://graph.microsoft.com/.default"

# Token cache. Microsoft mints client-credentials tokens with a 3600s
# lifetime; we refresh 600s early so we never present an about-to-expire
# token to Graph and trigger a 401-retry storm.
_TOKEN_REFRESH_SLACK = timedelta(seconds=600)
_TOKEN_DEFAULT_LIFETIME = timedelta(seconds=3600)

# Connect + read timeout for Graph calls. Graph delta on a large tenant
# can take several seconds to materialise the first page; 30s is the
# documented upper bound for a single page response.
_HTTP_TIMEOUT = httpx.Timeout(30.0, connect=10.0)


class IntuneGraphError(RuntimeError):
    """Raised on any non-recoverable Graph error.

    Wraps the upstream HTTP status + a sanitised message. The original
    response body MAY contain the device inventory or, on 401, an
    error description that quotes the client_id. Both are safe to
    surface to operators but not to embed in customer-visible error
    responses, so callers should ``str(exc)`` for logs and a static
    "MDM upstream error" string for any user-facing path.
    """

    def __init__(self, status: int, message: str):
        super().__init__(f"Intune Graph error {status}: {message}")
        self.status = status
        self.message = message


class IntuneClient:
    """Async client for the subset of Microsoft Graph F2 needs.

    Construction does not perform any I/O. The first call to
    :meth:`fetch_managed_devices_delta` triggers token acquisition.

    Thread-safety: the client holds a single :class:`httpx.AsyncClient`
    and an unsynchronised token cache. Callers are expected to keep
    one instance per polling task (the F2 lifespan wiring does so).
    Concurrent calls from a single task are safe; sharing across
    tasks would race on the token refresh and is unsupported.
    """

    def __init__(
        self,
        *,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        http_client: httpx.AsyncClient | None = None,
    ):
        if not (tenant_id and client_id and client_secret):
            raise ValueError(
                "IntuneClient requires non-empty tenant_id, client_id, "
                "and client_secret",
            )
        self._tenant_id = tenant_id
        self._client_id = client_id
        # Kept private; never logged, never put in __repr__. The
        # secret is the only credential between this process and the
        # customer tenant.
        self._client_secret = client_secret

        self._http = http_client or httpx.AsyncClient(timeout=_HTTP_TIMEOUT)
        self._owns_http = http_client is None

        self._token: str | None = None
        self._token_expires_at: datetime | None = None

    async def aclose(self) -> None:
        """Release the underlying httpx client if we created it."""
        if self._owns_http:
            await self._http.aclose()

    # ── Auth ──────────────────────────────────────────────────────────

    async def _ensure_token(self) -> str:
        """Return a valid bearer token, refreshing if needed.

        The cached token is reused until it falls within
        :data:`_TOKEN_REFRESH_SLACK` of expiry. On refresh we re-POST
        the client_credentials grant; the response's ``expires_in`` is
        honoured rather than assumed (Azure occasionally returns
        shorter lifetimes for newly-registered apps).
        """
        now = datetime.now(timezone.utc)
        if (
            self._token is not None
            and self._token_expires_at is not None
            and now + _TOKEN_REFRESH_SLACK < self._token_expires_at
        ):
            return self._token

        url = f"{_LOGIN_HOST}/{self._tenant_id}/oauth2/v2.0/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "scope": _GRAPH_SCOPE,
        }
        try:
            resp = await self._http.post(url, data=data)
        except httpx.HTTPError as exc:
            raise IntuneGraphError(
                0, f"token request transport error: {type(exc).__name__}",
            ) from exc

        if resp.status_code != 200:
            # Body MAY contain ``error_description`` quoting the
            # client_id. Surface a sanitised message; never log the
            # body verbatim because some failure modes echo the
            # secret back.
            raise IntuneGraphError(
                resp.status_code,
                "token endpoint returned non-200 (check tenant_id, "
                "client_id, client_secret, and admin consent)",
            )

        payload = resp.json()
        access_token = payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise IntuneGraphError(
                200, "token endpoint returned 200 without access_token",
            )

        lifetime_s = payload.get("expires_in", _TOKEN_DEFAULT_LIFETIME.total_seconds())
        try:
            lifetime = timedelta(seconds=int(lifetime_s))
        except (TypeError, ValueError):
            lifetime = _TOKEN_DEFAULT_LIFETIME

        self._token = access_token
        self._token_expires_at = now + lifetime
        return access_token

    # ── Managed devices ───────────────────────────────────────────────

    async def fetch_managed_devices_delta(
        self,
        delta_link: str | None = None,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Fetch one round of managed-device deltas.

        Args:
            delta_link: Opaque URL returned as ``@odata.deltaLink`` on
                a prior call. ``None`` triggers a full sync against
                the standard ``managedDevices/delta`` endpoint.

        Returns:
            ``(devices, next_delta_link)``. ``devices`` is the union
            of all pages walked in this call (Graph paginates via
            ``@odata.nextLink``; the delta endpoint terminates each
            walk with a ``@odata.deltaLink`` that the caller should
            persist for the next round).

        Raises:
            IntuneGraphError: On any non-200 Graph response or transport
                error after retries have been exhausted.
        """
        token = await self._ensure_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

        url = delta_link or f"{_GRAPH_BASE}/deviceManagement/managedDevices/delta"
        devices: list[dict[str, Any]] = []
        next_delta: str | None = None
        # Cap the walk so a runaway tenant cannot stall the polling
        # loop. 200 pages * 1000 rows/page = 200k devices. Anyone with
        # more than that needs a different ingestion strategy anyway.
        pages_left = 200

        while pages_left > 0:
            try:
                resp = await self._http.get(url, headers=headers)
            except httpx.HTTPError as exc:
                raise IntuneGraphError(
                    0,
                    f"managedDevices transport error: {type(exc).__name__}",
                ) from exc

            if resp.status_code == 401:
                # Token expired between issuance and this call (rare,
                # but Azure clock skew + lifetime variance hits this).
                # One forced refresh + retry, then surface.
                self._token = None
                self._token_expires_at = None
                token = await self._ensure_token()
                headers["Authorization"] = f"Bearer {token}"
                resp = await self._http.get(url, headers=headers)

            if resp.status_code != 200:
                # 429 carries a Retry-After header; the poller wraps
                # this in its own exponential backoff so we don't
                # honour it inline.
                raise IntuneGraphError(
                    resp.status_code,
                    "managedDevices endpoint returned non-200",
                )

            payload = resp.json()
            page = payload.get("value", [])
            if isinstance(page, list):
                devices.extend(page)

            next_link = payload.get("@odata.nextLink")
            delta_out = payload.get("@odata.deltaLink")

            if delta_out:
                next_delta = delta_out
                break
            if next_link:
                url = next_link
                pages_left -= 1
                continue
            # No nextLink and no deltaLink — terminal page that did
            # not emit a delta. Graph occasionally returns this on
            # an empty tenant; fall back to "no delta" so the caller
            # forces a full sync next round.
            break

        return devices, next_delta


def map_compliance_state(graph_state: str | None) -> str:
    """Translate the Graph ``complianceState`` enum to the claim shape.

    Graph values: ``compliant``, ``noncompliant``, ``conflict``,
    ``error``, ``inGracePeriod``, ``configManager``, ``unknown``.
    Claim values (schema sez. 1): ``compliant``, ``non_compliant``,
    ``unknown``.

    The conservative mapping: only the unambiguous ``compliant`` and
    ``noncompliant`` map through; everything else (transient grace,
    conflict, error, unknown) falls into ``unknown`` so the effective
    tier downgrades and never grants policy access on stale or
    uncertain state.
    """
    if graph_state == "compliant":
        return "compliant"
    if graph_state == "noncompliant":
        return "non_compliant"
    return "unknown"


def project_device_row(graph_device: Mapping[str, Any]) -> dict[str, Any]:
    """Project a Graph ``managedDevice`` JSON into our cache row shape.

    Only the fields F2 actually persists. Unknown future fields stay
    in ``raw_payload`` for forensic queries; the projection here is
    the contract the rest of the proxy reads.
    """
    return {
        "device_id": str(graph_device.get("id") or ""),
        "compliance": map_compliance_state(graph_device.get("complianceState")),
        "azure_ad_device_id": graph_device.get("azureADDeviceId"),
        "user_principal_name": graph_device.get("userPrincipalName"),
        "device_name": graph_device.get("deviceName"),
        "manufacturer": graph_device.get("manufacturer"),
        "serial_number": graph_device.get("serialNumber"),
    }
