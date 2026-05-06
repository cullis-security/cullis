"""Device-code enrollment flow — Connector side of Phase 2 (#64).

Mirror of the server API in ``mcp_proxy.enrollment``:

1. Generate EC P-256 keypair locally (private key never leaves the machine).
2. ``POST /v1/enrollment/start`` with pubkey + self-declared identity.
3. Print the ``enroll_url`` to stderr — the user shares it with the admin
   (or opens it themselves for future HTML form flavour) so the admin can
   verify the request in the dashboard.
4. Poll ``GET /v1/enrollment/{session_id}/status`` at the interval the
   server suggested; stop on terminal states (approved / rejected /
   expired).
5. On ``approved``: persist cert + metadata via the identity store, return
   the new :class:`IdentityBundle` to the caller.
"""
from __future__ import annotations

import logging
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from cryptography import x509

from cullis_connector.identity import (
    IdentityBundle,
    generate_keypair,
    public_key_to_pem,
    save_identity,
)
from cullis_connector.identity.store import IdentityMetadata, load_identity


_log = logging.getLogger("cullis_connector.enrollment")


class EnrollmentFailed(Exception):
    """Raised for any non-success terminal outcome of the flow."""


@dataclass
class RequesterInfo:
    name: str
    email: str
    reason: str | None = None
    device_info: str | None = None


def enroll(
    *,
    site_url: str,
    config_dir: Path,
    requester: RequesterInfo,
    verify_tls: bool | str = True,
    request_timeout_s: float = 10.0,
    max_wait_s: int = 30 * 60,
    poll_sink=sys.stderr,
) -> IdentityBundle:
    """Full device-code enrollment, blocking until admin decides or TTL expires.

    Parameters
    ----------
    site_url:
        Base URL of the Cullis Site (e.g. ``https://cullis.acme.local:9443``).
    config_dir:
        Where to persist the resulting identity (``<config_dir>/identity/``).
    requester:
        Self-declared identity — the admin is the authority that decides
        agent_id, capabilities, and groups. Stored for audit only.
    poll_sink:
        Stream for human-readable progress output. Defaults to stderr so
        it never pollutes an MCP stdio transport when the caller also
        happens to be a server process.
    """
    site_url = site_url.rstrip("/")
    private_key = generate_keypair()
    pubkey_pem = public_key_to_pem(private_key.public_key()).decode()

    # ADR-014 PR-C: the cert the Mastio signs at approval is the
    # agent's credential — no api_key is minted on either side.

    # F-B-11 Phase 3d (#181) — generate the DPoP keypair locally, submit
    # the public JWK at start, persist the private half alongside the
    # identity on approval. The server computes its RFC 7638 thumbprint
    # and stores it on ``internal_agents.dpop_jkt`` (#207) so every
    # proof the SDK later signs is pinned to this specific keypair.
    from cullis_sdk.dpop import DpopKey
    dpop_key = DpopKey.generate()
    dpop_public_jwk = dpop_key.public_jwk

    start_resp = _start(
        site_url=site_url,
        pubkey_pem=pubkey_pem,
        requester=requester,
        dpop_jwk=dpop_public_jwk,
        verify_tls=verify_tls,
        timeout_s=request_timeout_s,
        private_key=private_key,
    )
    session_id = start_resp["session_id"]
    enroll_url = start_resp["enroll_url"]
    poll_interval_s = int(start_resp.get("poll_interval_s", 5))

    print(
        "Cullis enrollment started.\n"
        f"  Share this URL with your admin: {enroll_url}\n"
        "  Waiting for admin decision (will poll until approved, rejected, "
        f"or the session expires at {start_resp.get('expires_at', 'n/a')}).",
        file=poll_sink,
        flush=True,
    )

    record = _poll_until_resolved(
        site_url=site_url,
        session_id=session_id,
        poll_interval_s=poll_interval_s,
        max_wait_s=max_wait_s,
        verify_tls=verify_tls,
        timeout_s=request_timeout_s,
        poll_sink=poll_sink,
        private_key=private_key,
    )

    status = record.get("status")
    if status == "rejected":
        raise EnrollmentFailed(
            f"Admin rejected the enrollment: "
            f"{record.get('rejection_reason') or '(no reason given)'}"
        )
    if status == "expired":
        raise EnrollmentFailed("Enrollment session expired before admin decided.")
    if status != "approved":
        raise EnrollmentFailed(f"Unexpected enrollment status '{status}'")

    cert_pem = record.get("cert_pem")
    if not cert_pem:
        raise EnrollmentFailed("Approved enrollment is missing cert_pem — server bug?")

    agent_id = str(record.get("agent_id") or "")
    capabilities = list(record.get("capabilities") or [])

    metadata = IdentityMetadata(
        agent_id=agent_id,
        capabilities=capabilities,
        site_url=site_url,
        issued_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
    save_identity(
        config_dir=config_dir,
        cert_pem=cert_pem,
        private_key=private_key,
        ca_chain_pem=None,  # Phase 2c will fetch the CA chain from the Site.
        metadata=metadata,
        dpop_private_jwk=dpop_key.private_jwk(),
    )

    print(
        f"✓ Enrollment approved. Agent ID assigned: {agent_id}",
        file=poll_sink,
        flush=True,
    )

    return load_identity(config_dir)


# ── Internals ────────────────────────────────────────────────────────────


def _build_pop_signature(private_key, pubkey_pem: str) -> str:
    """H-csr-pop audit fix — sign the canonical proof string with the
    enrollment keypair so the server can verify the submitter
    actually controls the matching private key.

    Without this proof a hostile caller could submit *someone else's*
    public key (observed in logs / leaked) and have the admin issue
    a cert tied to it: useless to the attacker (they don't have the
    private key), but a griefing / impersonation surface against the
    real owner of the keypair.
    """
    import base64 as _b64
    import hashlib as _hashlib

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    public_key = serialization.load_pem_public_key(pubkey_pem.encode())
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = _hashlib.sha256(der).hexdigest()
    canonical = f"enrollment-pop:v1|{fingerprint}".encode("utf-8")

    if isinstance(private_key, rsa.RSAPrivateKey):
        sig = private_key.sign(
            canonical,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        sig = private_key.sign(canonical, ec.ECDSA(hashes.SHA256()))
    else:
        raise EnrollmentFailed(
            f"Unsupported enrollment key type: {type(private_key).__name__}"
        )
    return _b64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")


def _start(
    *,
    site_url: str,
    pubkey_pem: str,
    requester: RequesterInfo,
    verify_tls: bool | str,
    timeout_s: float,
    dpop_jwk: dict | None = None,
    private_key=None,
) -> dict[str, Any]:
    body = {
        "pubkey_pem": pubkey_pem,
        "requester_name": requester.name,
        "requester_email": requester.email,
    }
    if requester.reason:
        body["reason"] = requester.reason
    if requester.device_info:
        body["device_info"] = requester.device_info
    # Shared-mode flag (Frontdesk container): when ``AMBASSADOR_MODE=shared``
    # is set on this Connector, the workload enrolls *itself* as a shared
    # multi-user host. The proxy reads ``ambassador_mode`` out of
    # ``device_info`` at approve() time to skip the auto-baseline binding —
    # capabilities scoped to MCP resources belong on user principals, not
    # on the container (see ADR-021 + memory note
    # ``feedback_frontdesk_shared_mode_capability_model``).
    import os as _os
    if _os.environ.get("AMBASSADOR_MODE", "").strip().lower() == "shared":
        body["device_info"] = _wrap_device_info_with_shared_mode(
            body.get("device_info"),
        )
    # F-B-11 Phase 3d — include the public DPoP JWK so Mastio can
    # compute + store its thumbprint on approve (wire added in #207).
    if dpop_jwk is not None:
        body["dpop_jwk"] = dpop_jwk
    if private_key is not None:
        body["pop_signature"] = _build_pop_signature(private_key, pubkey_pem)

    try:
        response = httpx.post(
            f"{site_url}/v1/enrollment/start",
            json=body,
            verify=verify_tls,
            timeout=timeout_s,
        )
    except httpx.HTTPError as exc:
        raise EnrollmentFailed(f"Could not reach Site at {site_url}: {exc}") from exc

    if response.status_code != 201:
        raise EnrollmentFailed(
            f"Site rejected enrollment start (HTTP {response.status_code}): "
            f"{response.text[:300]}"
        )
    return response.json()


def _wrap_device_info_with_shared_mode(device_info: str | None) -> str:
    """Embed ``ambassador_mode=shared`` into the ``device_info`` JSON.

    If the operator already passed a JSON object as ``device_info``, merge
    in the flag (without overwriting an explicit user-supplied value). If
    they passed a plain string, nest it under ``raw`` so nothing is lost.
    """
    import json as _json
    payload: dict[str, Any] = {"ambassador_mode": "shared"}
    if device_info:
        try:
            existing = _json.loads(device_info)
        except (TypeError, ValueError):
            payload["raw"] = device_info
        else:
            if isinstance(existing, dict):
                existing.setdefault("ambassador_mode", "shared")
                return _json.dumps(existing)
            payload["raw"] = device_info
    return _json.dumps(payload)


def _build_enrollment_proof(private_key, session_id: str) -> str:
    """M-onb-1 audit fix — sign the canonical proof string with the
    enrollment keypair so the server can verify the poller is the
    same client that called ``/v1/enrollment/start``.

    Without this header the server returns the bare status flag and
    withholds ``cert_pem`` / ``agent_id`` / ``capabilities`` — an
    attacker who guesses or steals a session_id no longer pulls the
    issued cert.
    """
    import base64 as _b64

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    canonical = f"enrollment-status:v1|{session_id}".encode("utf-8")
    if isinstance(private_key, rsa.RSAPrivateKey):
        sig = private_key.sign(
            canonical,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        sig = private_key.sign(canonical, ec.ECDSA(hashes.SHA256()))
    else:
        raise EnrollmentFailed(
            f"Unsupported enrollment key type: {type(private_key).__name__}"
        )
    return _b64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")


def _poll_until_resolved(
    *,
    site_url: str,
    session_id: str,
    poll_interval_s: int,
    max_wait_s: int,
    verify_tls: bool | str,
    timeout_s: float,
    poll_sink,
    private_key,
) -> dict[str, Any]:
    deadline = time.monotonic() + max_wait_s
    poll_url = f"{site_url}/v1/enrollment/{session_id}/status"
    last_printed = 0.0
    proof = _build_enrollment_proof(private_key, session_id)
    proof_headers = {"X-Enrollment-Proof": proof}

    while True:
        try:
            response = httpx.get(
                poll_url,
                headers=proof_headers,
                verify=verify_tls,
                timeout=timeout_s,
            )
        except httpx.HTTPError as exc:
            _log.warning("poll transient error", extra={"err": str(exc)})
            if time.monotonic() >= deadline:
                raise EnrollmentFailed(
                    f"Giving up polling after {max_wait_s}s: {exc}"
                ) from exc
            time.sleep(poll_interval_s)
            continue

        if response.status_code == 404:
            raise EnrollmentFailed(
                "Enrollment session no longer exists — may have been expired "
                "and purged."
            )
        if response.status_code != 200:
            raise EnrollmentFailed(
                f"Site returned HTTP {response.status_code} during poll: "
                f"{response.text[:300]}"
            )

        record = response.json()
        if record.get("status") != "pending":
            return record

        now = time.monotonic()
        if now - last_printed > 60:
            waited = int(max_wait_s - (deadline - now))
            print(
                f"  … still waiting for admin decision ({waited}s elapsed)",
                file=poll_sink,
                flush=True,
            )
            last_printed = now

        if now >= deadline:
            raise EnrollmentFailed(
                f"Gave up after {max_wait_s}s without a decision — try again."
            )
        time.sleep(poll_interval_s)


def cert_fingerprint(cert: x509.Certificate) -> str:
    """SHA-256 of the cert DER, 64-char hex. Used for operator verification."""
    import hashlib
    return hashlib.sha256(cert.public_bytes(encoding=_DER)).hexdigest()


# local alias to avoid a circular-looking import in the helper above
from cryptography.hazmat.primitives.serialization import Encoding as _SerializationEncoding
_DER = _SerializationEncoding.DER
