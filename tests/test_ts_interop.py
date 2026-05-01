"""
Cross-language E2E interop between the TypeScript SDK and the Python SDK.

Verifies that blobs produced by one SDK can be decrypted by the other, for
both RSA-OAEP and ECDH+HKDF key wrapping. Also guards against regressions of
the base64url no-pad bug (TS emits no-pad, Python must tolerate).

Skipped automatically if Node.js or the built TS SDK (sdk-ts/dist) are absent.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from cullis_sdk.crypto.e2e import decrypt_from_agent, encrypt_for_agent

REPO_ROOT = Path(__file__).resolve().parent.parent
TS_DIST = REPO_ROOT / "sdk-ts" / "dist" / "crypto.js"
HARNESS = REPO_ROOT / "tests" / "interop" / "ts_roundtrip.mjs"

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None or not TS_DIST.exists(),
    reason="node or built sdk-ts/dist missing — run `cd sdk-ts && npm run build`",
)


def _pem_keypair(kind: str) -> tuple[str, str]:
    if kind == "ec":
        priv = ec.generate_private_key(ec.SECP256R1())
    elif kind == "rsa":
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    else:
        raise ValueError(kind)
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv_pem, pub_pem


def _self_signed_cert(priv_pem: str, agent_id: str, org_id: str) -> str:
    """Build a self-signed cert for ``agent_id`` from the given private key.

    H7 audit: ``verifyMessageSignature`` rejects bare SPKI public keys
    and binds the cert subject to ``senderAgentId``. Test fixtures that
    used to ship a bare pubkey now ship a self-signed cert with
    ``CN=agent_id`` and ``O=org_id`` to mirror the production identity
    binding (see ``cullis_sdk.crypto._cert_trust``).
    """
    import datetime as _dt

    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.x509.oid import NameOID

    priv = serialization.load_pem_private_key(priv_pem.encode(), password=None)
    subject = _x509.Name([
        _x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
        _x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_id),
    ])
    builder = (
        _x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(priv.public_key())
        .serial_number(_x509.random_serial_number())
        .not_valid_before(_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(minutes=5))
        .not_valid_after(_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(hours=1))
    )
    cert = builder.sign(priv, _hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _run_node(mode: str, payload: dict) -> dict:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(payload, f)
        fpath = f.name
    result = subprocess.run(
        ["node", str(HARNESS), mode, f"--input={fpath}"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"node harness failed: {result.stderr}")
    return json.loads(result.stdout)


@pytest.mark.parametrize("kind", ["ec", "rsa"])
def test_python_encrypt_to_ts_decrypt(kind: str) -> None:
    priv_pem, pub_pem = _pem_keypair(kind)
    payload = {"kind": kind, "direction": "py->ts", "n": 7}
    blob = encrypt_for_agent(
        pub_pem,
        payload,
        "inner-sig-from-python",
        "sess-py2ts",
        "orgA::python-sender",
        client_seq=11,
    )
    out = _run_node(
        "decrypt",
        {
            "recipient_priv_pem": priv_pem,
            "blob": blob,
            "session_id": "sess-py2ts",
            "sender_agent_id": "orgA::python-sender",
            "client_seq": 11,
        },
    )
    assert out["payload"] == payload
    assert out["inner_signature"] == "inner-sig-from-python"


@pytest.mark.parametrize("kind", ["ec", "rsa"])
def test_ts_encrypt_to_python_decrypt(kind: str) -> None:
    priv_pem, pub_pem = _pem_keypair(kind)
    payload = {"kind": kind, "direction": "ts->py", "n": 13}
    out = _run_node(
        "encrypt",
        {
            "recipient_pub_pem": pub_pem,
            "payload": payload,
            "inner_signature": "inner-sig-from-ts",
            "session_id": "sess-ts2py",
            "sender_agent_id": "orgB::ts-sender",
            "client_seq": 3,
        },
    )
    blob = out["blob"]
    decoded_payload, inner_sig = decrypt_from_agent(
        priv_pem,
        blob,
        "sess-ts2py",
        "orgB::ts-sender",
        client_seq=3,
    )
    assert decoded_payload == payload
    assert inner_sig == "inner-sig-from-ts"


@pytest.mark.parametrize("kind", ["ec", "rsa"])
def test_python_sign_ts_verify(kind: str) -> None:
    """Python signs a canonical message; TS verifies. Proves signature-alg
    auto-dispatch matches Python's RSA-PSS / ECDSA selection."""
    from app.auth.message_signer import sign_message

    priv_pem, _ = _pem_keypair(kind)
    cert_pem = _self_signed_cert(priv_pem, "orgA::alice", "orgA")
    payload = {"kind": kind, "k": "py-sign"}
    nonce = "n-py-ts"
    ts = 1700000000
    signature = sign_message(priv_pem, "s1", "orgA::alice", nonce, ts, payload, 5)
    out = _run_node(
        "verify",
        {
            "sender_pub_pem": cert_pem,
            "signature": signature,
            "session_id": "s1",
            "sender_agent_id": "orgA::alice",
            "nonce": nonce,
            "timestamp": ts,
            "payload": payload,
            "client_seq": 5,
        },
    )
    assert out.get("valid") is True, out


@pytest.mark.parametrize("kind", ["ec", "rsa"])
def test_ts_sign_python_verify(kind: str) -> None:
    """TS signs; Python verifies against the raw pubkey (matches broker logic)."""
    import base64 as _b64

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.hazmat.primitives.asymmetric import padding as _padding
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

    priv_pem, pub_pem = _pem_keypair(kind)
    payload = {"kind": kind, "k": "ts-sign"}
    nonce = "n-ts-py"
    ts = 1700000001
    out = _run_node(
        "sign",
        {
            "sender_priv_pem": priv_pem,
            "session_id": "s2",
            "sender_agent_id": "orgB::bob",
            "nonce": nonce,
            "timestamp": ts,
            "payload": payload,
            "client_seq": 9,
        },
    )
    signature = out["signature"]
    import json as _json
    payload_str = _json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    canonical = f"s2|orgB::bob|{nonce}|{ts}|9|{payload_str}".encode()
    sig_bytes = _b64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
    pub_key = serialization.load_pem_public_key(pub_pem.encode())
    if isinstance(pub_key, _rsa.RSAPublicKey):
        pub_key.verify(
            sig_bytes, canonical,
            _padding.PSS(
                mgf=_padding.MGF1(hashes.SHA256()),
                salt_length=_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    else:
        assert isinstance(pub_key, _ec.EllipticCurvePublicKey)
        pub_key.verify(sig_bytes, canonical, _ec.ECDSA(hashes.SHA256()))


# --------------------------------------------------------------------------
# F-A-2 regression: canonical JSON cross-language parity for non-ASCII input.
#
# Before the fix, TS `JSON.stringify` emitted raw UTF-8 for code points
# >= U+007F while Python `json.dumps(..., ensure_ascii=True)` emitted
# `\uXXXX`. The two sides signed the same canonical-string template but
# produced divergent bytes, so signatures over any non-ASCII payload never
# verified cross-language. These tests guard both directions.
# --------------------------------------------------------------------------

# Payloads exercising the boundary cases Python's ensure_ascii=True targets:
#   - non-ASCII BMP (latin-1 supplement: U+00E9)
#   - astral code point (U+1F389 "🎉") that JS emits as a UTF-16 surrogate pair
#   - control/DEL boundary (U+0000, U+007F, U+0080, U+00FF)
#   - pure ASCII (must still match byte-for-byte)
_CANONICAL_PAYLOADS: list[tuple[str, dict]] = [
    ("latin1", {"name": "José"}),
    ("astral", {"msg": "café 🎉"}),
    ("controls", {"k": "\u0000\u007f\u0080\u00ff"}),
    ("ascii", {"a": 1, "b": "hello"}),
    ("nested_unicode", {"outer": {"inner": "αβγ", "list": ["日本語", "🔒"]}}),
]


def _python_canonical(payload: dict) -> tuple[str, str]:
    """Python-side canonical JSON + SHA-256 hex, matching the signer spec."""
    import hashlib

    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return canonical, digest


@pytest.mark.parametrize("label,payload", _CANONICAL_PAYLOADS, ids=[p[0] for p in _CANONICAL_PAYLOADS])
def test_canonical_json_parity_python_vs_ts(label: str, payload: dict) -> None:
    """Canonical JSON bytes + SHA-256 must be byte-identical across languages."""
    py_canonical, py_hash = _python_canonical(payload)
    out = _run_node("canonical", {"payload": payload})
    assert out["canonical"] == py_canonical, (
        f"canonical divergence for {label}: py={py_canonical!r} ts={out['canonical']!r}"
    )
    assert out["hash"] == py_hash, f"hash divergence for {label}"


@pytest.mark.parametrize("label,payload", _CANONICAL_PAYLOADS, ids=[p[0] for p in _CANONICAL_PAYLOADS])
def test_python_sign_ts_verify_non_ascii(label: str, payload: dict) -> None:
    """Python signs a non-ASCII payload; TS must verify (F-A-2 regression)."""
    from app.auth.message_signer import sign_message

    priv_pem, _ = _pem_keypair("ec")
    cert_pem = _self_signed_cert(priv_pem, "orgA::alice", "orgA")
    nonce = f"n-py-ts-{label}"
    ts = 1700000100
    signature = sign_message(priv_pem, "s1", "orgA::alice", nonce, ts, payload, 5)
    out = _run_node(
        "verify",
        {
            "sender_pub_pem": cert_pem,
            "signature": signature,
            "session_id": "s1",
            "sender_agent_id": "orgA::alice",
            "nonce": nonce,
            "timestamp": ts,
            "payload": payload,
            "client_seq": 5,
        },
    )
    assert out.get("valid") is True, f"{label}: {out}"


@pytest.mark.parametrize("label,payload", _CANONICAL_PAYLOADS, ids=[p[0] for p in _CANONICAL_PAYLOADS])
def test_ts_sign_python_verify_non_ascii(label: str, payload: dict) -> None:
    """TS signs a non-ASCII payload; Python must verify (F-A-2 regression)."""
    import base64 as _b64

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.hazmat.primitives.asymmetric import padding as _padding
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

    priv_pem, pub_pem = _pem_keypair("ec")
    nonce = f"n-ts-py-{label}"
    ts = 1700000200
    out = _run_node(
        "sign",
        {
            "sender_priv_pem": priv_pem,
            "session_id": "s2",
            "sender_agent_id": "orgB::bob",
            "nonce": nonce,
            "timestamp": ts,
            "payload": payload,
            "client_seq": 9,
        },
    )
    signature = out["signature"]
    payload_str = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    canonical = f"s2|orgB::bob|{nonce}|{ts}|9|{payload_str}".encode()
    sig_bytes = _b64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
    pub_key = serialization.load_pem_public_key(pub_pem.encode())
    if isinstance(pub_key, _rsa.RSAPublicKey):
        pub_key.verify(
            sig_bytes, canonical,
            _padding.PSS(mgf=_padding.MGF1(hashes.SHA256()), salt_length=_padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    else:
        assert isinstance(pub_key, _ec.EllipticCurvePublicKey)
        pub_key.verify(sig_bytes, canonical, _ec.ECDSA(hashes.SHA256()))


# Pinned golden hashes. These values are derived from the Python spec
# (`json.dumps(..., sort_keys=True, separators=(",",":"), ensure_ascii=True)`
# then SHA-256). If either language drifts, this list breaks loudly and the
# bug is obvious — it's not a symmetry-only check but a concrete spec anchor.
_GOLDEN_HASHES: list[tuple[dict, str, str]] = [
    (
        {"a": 1, "b": "hello"},
        '{"a":1,"b":"hello"}',
        "d84ab9f85753473707229d00b92623f0f9a1b8b9bf69763fc5cfc692b56c236b",
    ),
    (
        {"name": "José"},
        '{"name":"Jos\\u00e9"}',
        "782f7fb6e7349477ad0878467428033420f78fc728c94d07ebb1d49d7cbae82e",
    ),
    (
        {"msg": "café 🎉"},
        '{"msg":"caf\\u00e9 \\ud83c\\udf89"}',
        "10c53dc2027ebf7f5f31e8d5191382d676bbf62f847bae56a09414891cd2dd6a",
    ),
    (
        {"k": "\u0000\u007f\u0080\u00ff"},
        '{"k":"\\u0000\\u007f\\u0080\\u00ff"}',
        "8506cd934650b2d8920884f9cdb74037de8b53e9ebdc7da337927921230bef23",
    ),
    (
        {"outer": {"inner": "αβγ", "list": ["日本語", "🔒"]}},
        None,  # computed below — exact string is long, we just pin the hash
        None,
    ),
]


def test_canonical_json_golden_hashes() -> None:
    """Pinned SHA-256 values that both Python and TS must reproduce."""
    import hashlib

    for payload, expected_canonical, expected_hash in _GOLDEN_HASHES:
        py_canonical, py_hash = _python_canonical(payload)
        if expected_canonical is not None:
            assert py_canonical == expected_canonical, (
                f"Python canonical drift for {payload!r}: got {py_canonical!r}"
            )
        if expected_hash is not None:
            assert py_hash == expected_hash, (
                f"Python hash drift for {payload!r}: got {py_hash}"
            )
        out = _run_node("canonical", {"payload": payload})
        assert out["canonical"] == py_canonical
        assert out["hash"] == py_hash
        # Redundant self-check so regenerating the golden file is trivial.
        assert hashlib.sha256(py_canonical.encode("utf-8")).hexdigest() == py_hash


def test_ts_blob_has_no_base64_padding() -> None:
    """
    Guards against regressions of the TS→Python base64 padding bug.
    All base64url fields emitted by the TS SDK must not end with '='.
    """
    _, pub_pem = _pem_keypair("ec")
    out = _run_node(
        "encrypt",
        {
            "recipient_pub_pem": pub_pem,
            "payload": {"x": 1},
            "inner_signature": "sig",
            "session_id": "s",
            "sender_agent_id": "a",
        },
    )
    blob = out["blob"]
    for field in ("ciphertext", "iv", "encrypted_key", "ephemeral_pubkey"):
        if field in blob:
            assert not blob[field].endswith("="), (
                f"TS SDK emitted padded base64url for {field}; "
                f"server decoders rely on no-pad convention"
            )
