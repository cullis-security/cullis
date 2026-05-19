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
    enable_hw_attestation: bool = True,
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

    # ADR-032 F3: best-effort TPM 2.0 attestation. detect_best_keystore
    # returns a soft keystore when the optional ``tpm2-pytss`` dep is
    # absent or no TPM device is reachable; the enrollment then carries
    # no attestation half and Mastio assigns the lower effective tier.
    attestation = _maybe_collect_tpm_attestation(
        site_url=site_url,
        pubkey_pem=pubkey_pem,
        verify_tls=verify_tls,
        timeout_s=request_timeout_s,
        enabled=enable_hw_attestation,
        sink=poll_sink,
    )

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
        attestation=attestation,
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


_MIN_MASTIO_VERSION_FOR_WORKLOAD = (0, 5, 0)


def _parse_semver(raw: str) -> tuple[int, int, int] | None:
    """Return ``(major, minor, patch)`` or ``None`` for unparseable / dev."""
    if not raw or raw == "dev":
        return None
    # Strip a leading ``v`` defensively in case CULLIS_MASTIO_VERSION
    # diverges from the no-v image convention (memory note
    # ``mastio-release-tag-convention``).
    clean = raw.lstrip("v")
    # Trim pre-release / build metadata (``0.5.0-rc1``, ``0.5.0+gha``).
    head = clean.split("-", 1)[0].split("+", 1)[0]
    try:
        major, minor, patch = (int(part) for part in head.split("."))
    except ValueError:
        return None
    return major, minor, patch


def _check_mastio_version_for_shared_mode(
    *,
    site_url: str,
    verify_tls: bool | str,
    timeout_s: float,
) -> None:
    """Refuse the enrollment when the target Mastio is too old for
    ADR-034 §2 workload identity. See ``_start`` for the call site.

    Raises :class:`EnrollmentFailed` with a message the operator can
    act on. The ``GET /health`` endpoint is unauthenticated and is the
    same one Docker healthchecks already use, so the probe doesn't
    require any setup work upstream.
    """
    health_url = f"{site_url.rstrip('/')}/health"
    try:
        response = httpx.get(
            health_url, verify=verify_tls, timeout=timeout_s,
        )
    except httpx.HTTPError as exc:
        raise EnrollmentFailed(
            f"Could not probe Mastio /health at {health_url} for "
            f"version compatibility: {exc}"
        ) from exc

    if response.status_code != 200:
        raise EnrollmentFailed(
            f"Mastio /health returned HTTP {response.status_code} — "
            "expected 200 with a ``version`` field."
        )

    try:
        body = response.json()
    except ValueError as exc:
        raise EnrollmentFailed(
            f"Mastio /health returned a non-JSON body: {exc}"
        ) from exc

    version_raw = (body.get("version") or "").strip()
    parsed = _parse_semver(version_raw)
    if parsed is None:
        # ``dev`` or unparseable — treat as a developer Mastio and let
        # the operator proceed. Production Mastios always inject
        # CULLIS_MASTIO_VERSION at image build time.
        return
    if parsed < _MIN_MASTIO_VERSION_FOR_WORKLOAD:
        min_str = ".".join(str(p) for p in _MIN_MASTIO_VERSION_FOR_WORKLOAD)
        raise EnrollmentFailed(
            f"Mastio at {site_url} reports version {version_raw}, but "
            f"shared-mode Frontdesk requires Mastio >= {min_str} for "
            "workload principal-type enrollment (ADR-034 §2). Upgrade "
            "Mastio first, or set FRONTDESK_SKIP_VERSION_PROBE=1 to "
            "override (only for dev / staging where audit attribution "
            "as ``agent`` is acceptable)."
        )


def _start(
    *,
    site_url: str,
    pubkey_pem: str,
    requester: RequesterInfo,
    verify_tls: bool | str,
    timeout_s: float,
    dpop_jwk: dict | None = None,
    private_key=None,
    attestation: "_AttestationBundle | None" = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
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
        # ADR-034 §2 — declare the Frontdesk bundle as a ``workload``
        # principal so Mastio audit + reach policy treat the container
        # as the web-tier broker it is, not as an AI agent. Operators
        # who need to override (e.g. a one-off agent-only bundle in
        # shared topology) can set ``FRONTDESK_PRINCIPAL_TYPE=agent``
        # in the env explicitly.
        principal_type = (
            _os.environ.get("FRONTDESK_PRINCIPAL_TYPE", "").strip().lower()
            or "workload"
        )
        if principal_type in {"agent", "workload"}:
            body["principal_type"] = principal_type
        # ADR-034 §6 / PR-A compat note — Pydantic ``extra="ignore"``
        # on the Mastio enrollment schema means a pre-0.5 Mastio
        # silently drops ``principal_type`` and lands the Frontdesk
        # as ``agent``. Refuse to enroll against such a Mastio in
        # shared mode so the workload identity isn't silently
        # downgraded. Skip the check when ``FRONTDESK_SKIP_VERSION_PROBE``
        # is set (dev workflow against a source-checkout Mastio that
        # reports ``version=dev``).
        if _os.environ.get(
            "FRONTDESK_SKIP_VERSION_PROBE", "",
        ).strip().lower() not in {"1", "true", "yes"}:
            _check_mastio_version_for_shared_mode(
                site_url=site_url,
                verify_tls=verify_tls,
                timeout_s=timeout_s,
            )
    # F-B-11 Phase 3d — include the public DPoP JWK so Mastio can
    # compute + store its thumbprint on approve (wire added in #207).
    if dpop_jwk is not None:
        body["dpop_jwk"] = dpop_jwk
    if private_key is not None:
        body["pop_signature"] = _build_pop_signature(private_key, pubkey_pem)

    if attestation is not None:
        body["attestation_nonce_id"] = attestation.nonce_id
        body["tpm_quote_b64"] = attestation.quote_b64
        if attestation.manufacturer:
            body["tpm_manufacturer"] = attestation.manufacturer
        body["tpm_ek_cert_present"] = attestation.ek_cert_present

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


# ── ADR-032 F3: hardware attestation helpers ───────────────────────────


@dataclass
class _AttestationBundle:
    nonce_id: str
    quote_b64: str
    manufacturer: str | None
    ek_cert_present: bool


def _maybe_collect_tpm_attestation(
    *,
    site_url: str,
    pubkey_pem: str,
    verify_tls: bool | str,
    timeout_s: float,
    enabled: bool,
    sink,
) -> _AttestationBundle | None:
    """Best-effort: detect a hardware keystore, request a nonce, quote it.

    Returns ``None`` on any failure; the enrollment then proceeds with
    the soft path. This is intentionally NOT a fatal gate: Mastio refuses
    ``_attested`` capability when the claim is absent, so the security
    boundary lives server-side (memoria
    ``feedback_h4_convergent_pattern_fallback_insecure_default``).
    """
    if not enabled:
        return None

    import base64 as _b64

    try:
        from cullis_connector.keystore import detect_best_keystore
        keystore = detect_best_keystore(prefer_hardware=True)
    except Exception as exc:
        _log.info("keystore_detect_failed", extra={"err": str(exc)})
        return None

    claim = keystore.attestation_claim()
    if claim is None:
        # Soft keystore: nothing to attest.
        return None

    quote_fn = getattr(keystore, "generate_aik_quote", None)
    if quote_fn is None:
        return None

    try:
        nonce_resp = httpx.get(
            f"{site_url}/v1/enrollment/attestation-nonce",
            verify=verify_tls,
            timeout=timeout_s,
        )
    except httpx.HTTPError as exc:
        _log.info("attestation_nonce_unreachable", extra={"err": str(exc)})
        return None
    if nonce_resp.status_code != 200:
        _log.info(
            "attestation_nonce_status_not_ok",
            extra={"status": nonce_resp.status_code},
        )
        return None

    payload = nonce_resp.json()
    nonce_id = payload.get("nonce_id")
    nonce_b64 = payload.get("nonce_b64")
    if not nonce_id or not nonce_b64:
        return None
    try:
        nonce_bytes = _b64.urlsafe_b64decode(
            nonce_b64 + "=" * (-len(nonce_b64) % 4),
        )
    except Exception:
        return None

    try:
        quote_blob = quote_fn(nonce_bytes)
    except Exception as exc:
        _log.info("tpm_quote_failed", extra={"err": str(exc)})
        return None

    quote_b64 = _b64.urlsafe_b64encode(quote_blob).rstrip(b"=").decode()
    ek_cert_present = claim.strength == "hw_attested"

    print(
        f"  ✓ TPM attestation bundled (strength={claim.strength}, "
        f"manufacturer={claim.manufacturer or 'unknown'})",
        file=sink,
        flush=True,
    )
    return _AttestationBundle(
        nonce_id=str(nonce_id),
        quote_b64=quote_b64,
        manufacturer=claim.manufacturer,
        ek_cert_present=ek_cert_present,
    )


# local alias to avoid a circular-looking import in the helper above
from cryptography.hazmat.primitives.serialization import Encoding as _SerializationEncoding
_DER = _SerializationEncoding.DER
