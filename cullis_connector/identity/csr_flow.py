"""Local-mode post-login CSR flow — ADR-025 Phase 3.

When ``AUTH_MODE=local`` is active and a user successfully authenticates
through ``/api/auth/login`` the Connector mints a short-lived
UserPrincipal cert from Mastio so subsequent ``/v1/*`` traffic can be
signed with the user's own SPIFFE identity instead of the Connector's
agent identity.

This module wraps the heavy lifting that already lives in
``cullis_connector/ambassador/shared/provisioning.py``
(``UserProvisioner`` + ``SdkMastioCsrTransport``) with a thin local-mode
adapter that:

  - builds a 4-segment principal_id from the local user_name,
    ``CULLIS_FRONTDESK_TRUST_DOMAIN``, and
    ``CULLIS_FRONTDESK_ORG_ID``
  - delegates the keypair / CSR / Mastio call to ``UserProvisioner``
  - surfaces a typed ``LocalProvisioningError`` so the login router can
    map a Mastio failure to HTTP 502 + ``X-Cullis-Provisioning-Failed``
    without re-prompting for the password (the password verification
    has already succeeded by the time we get here)

The cache lives on ``app.state.local_user_cache`` (see ``web.py``) and
its eviction policy (LRU + TTL = ``DEFAULT_TTL_SECONDS`` = 1h, matches
Mastio's USER_CERT_TTL) means the cert middleware can fall through to
``get_or_provision`` on cache miss without coordinating with the login
router. Re-provisioning is transparent.

The trust_domain / org_id resolver is intentionally env-driven rather
than read from the Connector identity bundle. The Connector's enrolled
agent_id encodes ``<org>::<agent>`` only — the trust_domain is not
present in that triple. ADR-025 §3 documents this contract; v0.2 will
plumb the trust_domain through enrollment metadata so the env override
becomes optional.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Optional

from cullis_connector.ambassador.shared.credentials import (
    UserCredentialCache,
    UserCredentials,
)
from cullis_connector.ambassador.shared.provisioning import (
    MastioCsrError,
    MastioCsrTransport,
    UserProvisioner,
)

_log = logging.getLogger("cullis_connector.identity.csr_flow")


# Env vars the Frontdesk container already documents (see
# ``cullis_connector/ambassador/shared/wire.py``). Reused here so a
# deployment that sets them once works for both shared and local mode.
ENV_TRUST_DOMAIN = "CULLIS_FRONTDESK_TRUST_DOMAIN"
ENV_ORG_ID = "CULLIS_FRONTDESK_ORG_ID"

# Fallback values for laptop / dev installs that have not been wired
# through the Frontdesk env contract yet. Matches the laptop defaults
# used by ``ambassador/session_routes.py``.
DEFAULT_TRUST_DOMAIN = "laptop"
DEFAULT_ORG_ID = "local"

# Principal type segment for end users — fixed string, not derived
# from the username. ADR-020 §2 reserves the path component.
PRINCIPAL_TYPE_USER = "user"


class LocalProvisioningError(RuntimeError):
    """Raised when post-login Mastio CSR provisioning fails.

    Wraps the underlying transport error so the login router can choose
    a 502 response code without leaking which Mastio response code came
    back. Carries the original message for the operator audit trail.
    """


@dataclass(frozen=True)
class PrincipalCoordinates:
    """The 4-segment principal identifier for a local user.

    ``principal_id`` is the canonical SPIFFE-path form
    (``<td>/<org>/user/<user_name>``) used by every callsite that
    speaks to Mastio's ``/v1/principals/csr`` endpoint. ``spiffe_uri``
    is the SAN value embedded in the CSR.
    """

    trust_domain: str
    org_id: str
    user_name: str

    @property
    def principal_id(self) -> str:
        return f"{self.trust_domain}/{self.org_id}/{PRINCIPAL_TYPE_USER}/{self.user_name}"

    @property
    def spiffe_uri(self) -> str:
        return f"spiffe://{self.principal_id}"


def resolve_principal_coordinates(
    user_name: str,
    *,
    env: Optional[dict[str, str]] = None,
) -> PrincipalCoordinates:
    """Build a :class:`PrincipalCoordinates` from env + user_name.

    Reads ``CULLIS_FRONTDESK_TRUST_DOMAIN`` + ``CULLIS_FRONTDESK_ORG_ID``,
    falling back to ``laptop`` / ``local`` when either is missing or
    blank. Empty / whitespace ``user_name`` raises ``ValueError`` so a
    caller cannot accidentally mint a principal_id with an empty name
    component.
    """
    if not isinstance(user_name, str) or not user_name.strip():
        raise ValueError("user_name must be a non-empty string")
    e = env if env is not None else os.environ
    trust_domain = (e.get(ENV_TRUST_DOMAIN) or "").strip() or DEFAULT_TRUST_DOMAIN
    org_id = (e.get(ENV_ORG_ID) or "").strip() or DEFAULT_ORG_ID
    return PrincipalCoordinates(
        trust_domain=trust_domain,
        org_id=org_id,
        user_name=user_name.strip(),
    )


class LocalUserProvisioner:
    """Local-mode wrapper around :class:`UserProvisioner`.

    Constructed once at boot in ``web.build_app`` and stashed on
    ``app.state.local_provisioner``. The login router calls
    :meth:`provision_for_user` after a successful password check; the
    cert middleware calls :meth:`get_or_provision_for_user` per
    ``/v1/*`` request to resolve the cached creds (or re-mint on miss).

    All calls share a single :class:`UserCredentialCache` so a cache
    hit at one callsite is visible at the other. The cache lifetime
    matches the cert TTL so a stale cert cannot survive past its issued
    not_after timestamp.
    """

    def __init__(
        self,
        *,
        mastio: MastioCsrTransport,
        cache: UserCredentialCache,
        env: Optional[dict[str, str]] = None,
    ) -> None:
        self._mastio = mastio
        self._cache = cache
        self._env = env
        self._provisioner = UserProvisioner(mastio=mastio, cache=cache)

    @property
    def cache(self) -> UserCredentialCache:
        """Expose the underlying cache so the cert middleware can read directly."""
        return self._cache

    def coordinates_for(self, user_name: str) -> PrincipalCoordinates:
        return resolve_principal_coordinates(user_name, env=self._env)

    async def provision_for_user(self, user_name: str) -> UserCredentials:
        """Mint a fresh cert for ``user_name`` (cache hit ok).

        Raises :class:`LocalProvisioningError` on Mastio failure. The
        login router catches this so a successful password verification
        is not undone by a transient Mastio outage; the user is allowed
        to log in but ``/v1/*`` requests will 502 until the next
        ``/api/auth/reprovision`` succeeds.
        """
        coords = self.coordinates_for(user_name)
        try:
            cred = await self._provisioner.get_or_provision(
                principal_id=coords.principal_id,
                # ``UserProvisioner`` uses ``sso_subject`` only as a
                # log breadcrumb — the user_name is what disambiguates
                # principals locally.
                sso_subject=user_name,
            )
        except MastioCsrError as exc:
            _log.warning(
                "local provisioning failed user_name=%s principal=%s: %s",
                user_name, coords.principal_id, exc,
            )
            raise LocalProvisioningError(str(exc)) from exc
        return cred

    async def get_or_provision_for_user(self, user_name: str) -> UserCredentials:
        """Alias of :meth:`provision_for_user` — kept distinct so the
        cert middleware's intent reads as cache-first.
        """
        return await self.provision_for_user(user_name)

    async def invalidate(self, user_name: str) -> bool:
        coords = self.coordinates_for(user_name)
        return await self._cache.invalidate(coords.principal_id)


__all__ = [
    "DEFAULT_ORG_ID",
    "DEFAULT_TRUST_DOMAIN",
    "ENV_ORG_ID",
    "ENV_TRUST_DOMAIN",
    "PRINCIPAL_TYPE_USER",
    "LocalProvisioningError",
    "LocalUserProvisioner",
    "PrincipalCoordinates",
    "resolve_principal_coordinates",
]
