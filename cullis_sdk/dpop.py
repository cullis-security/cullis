"""DPoP keypair management for the egress surface (F-B-11 Phase 3c).

A persistent EC P-256 keypair the SDK uses to sign DPoP proofs on every
``/v1/egress/*`` request. Unlike the ephemeral ingress DPoP key (see
``cullis_sdk.auth.generate_dpop_keypair``), this one must survive
restarts — the server stores its RFC 7638 thumbprint in
``internal_agents.dpop_jkt`` (#204) and compares every proof against
it (#207). A fresh key would mean every session re-binds.

File layout, aligned with the Connector identity store:

    <config_dir>/identity/dpop.jwk     # private JWK, chmod 0600

Generate + persist on first use, load on subsequent runs. The public
JWK is submitted to ``/v1/enrollment/start`` via the ``dpop_jwk``
field that Phase 3b landed (#207); operators who are rotating an
already-enrolled agent use the admin endpoint ``POST /v1/admin/agents/
{id}/dpop-jwk`` from #206.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets as _pysecrets
import time
import uuid
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


_DEFAULT_KEY_FILENAME = "dpop.jwk"


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _default_base_dir() -> Path:
    """Where to put ``<agent_id>.jwk`` when the caller does not pick."""
    return Path.home() / ".cullis" / "dpop"


class DpopKey:
    """EC P-256 keypair with on-disk persistence for DPoP egress auth.

    Construct via :meth:`load_or_generate` (reads from disk, creates on
    first run) rather than calling ``__init__`` directly.

    Attributes
    ----------
    private_key:
        The in-memory ``cryptography`` EC private key — never written
        to the wire.
    public_jwk:
        The RFC 7517 public JWK dict ``{kty, crv, x, y}`` that the
        server persists and compares its thumbprint against.
    path:
        File-system location of the private JWK, or ``None`` when the
        key is held only in memory (CI / ephemeral runs).
    """

    def __init__(
        self,
        private_key: ec.EllipticCurvePrivateKey,
        public_jwk: dict,
        *,
        path: Path | None = None,
    ) -> None:
        if public_jwk.get("kty") != "EC" or public_jwk.get("crv") != "P-256":
            raise ValueError(
                "DpopKey only supports EC P-256; got "
                f"kty={public_jwk.get('kty')!r} crv={public_jwk.get('crv')!r}"
            )
        self.private_key = private_key
        self.public_jwk = dict(public_jwk)  # defensive copy
        self.path = path

    # ── factories ──────────────────────────────────────────────────

    @classmethod
    def generate(cls, *, path: Path | None = None) -> DpopKey:
        """Mint a fresh EC P-256 keypair. Optional ``path`` persists it."""
        priv = ec.generate_private_key(ec.SECP256R1())
        nums = priv.public_key().public_numbers()
        x = _b64url(nums.x.to_bytes(32, "big"))
        y = _b64url(nums.y.to_bytes(32, "big"))
        jwk = {"kty": "EC", "crv": "P-256", "x": x, "y": y}
        key = cls(priv, jwk, path=path)
        if path is not None:
            key.save(path)
        return key

    @classmethod
    def load(cls, path: Path) -> DpopKey:
        """Read a DpopKey from disk. Raises ``FileNotFoundError`` if absent."""
        text = path.read_text()
        blob = json.loads(text)
        priv_jwk = blob.get("private_jwk") or blob
        if "d" not in priv_jwk:
            raise ValueError(
                f"{path} does not contain a private JWK ('d' missing)"
            )
        priv = _ec_from_private_jwk(priv_jwk)
        public_jwk = {k: priv_jwk[k] for k in ("kty", "crv", "x", "y")}
        return cls(priv, public_jwk, path=path)

    @classmethod
    def load_or_generate(
        cls, agent_id: str, *, base_dir: Path | None = None,
    ) -> DpopKey:
        """Return the keypair for ``agent_id``, generating + persisting on
        first use.

        Layout is ``<base_dir>/<sanitised-agent-id>.jwk``. The default
        base dir is ``~/.cullis/dpop/``. The file is written with
        ``chmod 0600`` so a co-resident user cannot read it.
        """
        if base_dir is None:
            base_dir = _default_base_dir()
        base_dir.mkdir(parents=True, exist_ok=True)
        filename = _sanitise_agent_id(agent_id) + ".jwk"
        path = base_dir / filename
        if path.exists():
            return cls.load(path)
        return cls.generate(path=path)

    # ── persistence ────────────────────────────────────────────────

    def save(self, path: Path) -> None:
        """Write the private JWK to ``path`` with ``chmod 0600``.

        The parent directory is created if absent. The write is atomic
        via the tempfile-then-rename pattern — a crash between bytes
        leaves either the old file or the fully-written new one, never
        a half-written secret.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        priv_jwk = self.private_jwk()
        payload = json.dumps({"private_jwk": priv_jwk}, separators=(",", ":"))
        tmp = path.with_suffix(path.suffix + f".tmp-{_pysecrets.token_hex(8)}")
        tmp.write_text(payload)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        self.path = path

    def private_jwk(self) -> dict:
        """Private JWK including ``d``. Treat as secret — never log / wire."""
        priv_numbers = self.private_key.private_numbers()
        d = _b64url(priv_numbers.private_value.to_bytes(32, "big"))
        return {**self.public_jwk, "d": d}

    # ── proof signing ──────────────────────────────────────────────

    def thumbprint(self) -> str:
        """RFC 7638 JWK thumbprint of the public key — the jkt the
        server compares against ``internal_agents.dpop_jkt``."""
        required = {k: self.public_jwk[k] for k in ("crv", "kty", "x", "y")}
        canonical = json.dumps(required, sort_keys=True, separators=(",", ":"))
        return _b64url(hashlib.sha256(canonical.encode()).digest())

    def sign_proof(
        self,
        method: str,
        url: str,
        *,
        access_token: str | None = None,
        nonce: str | None = None,
        jti: str | None = None,
        iat: int | None = None,
    ) -> str:
        """Build + sign a DPoP proof JWT (RFC 9449).

        Parameters mirror ``cullis_sdk.auth.build_dpop_proof`` plus the
        key-pinning property: the ``jwk`` header is *this* persistent
        key, so every proof the SDK emits carries the thumbprint the
        server has already registered.
        """
        priv_pem = self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

        claims: dict = {
            "jti": jti or uuid.uuid4().hex,
            "htm": method.upper(),
            "htu": url,
            "iat": int(iat if iat is not None else time.time()),
        }
        if access_token is not None:
            claims["ath"] = _b64url(
                hashlib.sha256(access_token.encode()).digest()
            )
        if nonce is not None:
            claims["nonce"] = nonce

        return jwt.encode(
            claims,
            priv_pem,
            algorithm="ES256",
            headers={"typ": "dpop+jwt", "jwk": self.public_jwk},
        )


def _sanitise_agent_id(agent_id: str) -> str:
    """Turn an agent_id into a safe filename component.

    Agent IDs look like ``org::agent`` which contains ``:`` — illegal
    on Windows and a footgun on filesystems that treat it as a drive
    separator. Replace non-alphanumeric chars with ``_``; keep the
    original string recognisable enough for an operator grepping the
    directory.
    """
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in agent_id)


def _ec_from_private_jwk(jwk: dict) -> ec.EllipticCurvePrivateKey:
    """Rebuild the ``cryptography`` private key object from a JWK."""
    if jwk.get("crv") != "P-256":
        raise ValueError(f"unsupported crv {jwk.get('crv')!r}, expected P-256")
    d = int.from_bytes(_b64url_decode(jwk["d"]), "big")
    x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
    pub_numbers = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=ec.SECP256R1())
    priv_numbers = ec.EllipticCurvePrivateNumbers(
        private_value=d, public_numbers=pub_numbers,
    )
    return priv_numbers.private_key()


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)
