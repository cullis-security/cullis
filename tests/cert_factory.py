"""
Test infrastructure for the x509 PKI.

Generates ephemeral (in-memory) certificates for broker, orgs, and agents.
Org certificates are cached per test session
(same org_id → same CA cert), avoiding drift across multiple tests.

Typical usage in tests:
    from tests.cert_factory import make_assertion, get_org_ca_pem, init_broker_keys

    # In conftest.py (session scope):
    broker_priv, broker_pub = init_broker_keys()
    import app.auth.jwt as jwt_module
    jwt_module._broker_private_key_pem = broker_priv
    jwt_module._broker_public_key_pem = broker_pub

    # In _register_agent helper:
    ca_pem = get_org_ca_pem(org_id)
    assertion = make_assertion(agent_id, org_id)
"""
import base64
import datetime
import hashlib
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
import jwt

# ─────────────────────────────────────────────────────────────────────────────
# Ephemeral broker CA (generated once per process)
# ─────────────────────────────────────────────────────────────────────────────

_broker_ca_key: rsa.RSAPrivateKey | None = None
_broker_ca_cert: x509.Certificate | None = None

# Cache org CA: (org_id, key_type) → (org_ca_key, org_ca_cert)
_org_ca_cache: dict[tuple[str, str], tuple] = {}

# Cache agent cert: (agent_id, org_id, trust_domain, key_type) → (agent_key, agent_cert)
# Guarantees the same agent always uses the same key within a test run
_agent_cert_cache: dict[tuple, tuple] = {}

# Cache alternate cert: (agent_id, org_id, key_type) → (agent_key, agent_cert)
# Used for thumbprint pinning tests — different key, same identity
_agent_alt_cert_cache: dict[tuple, tuple] = {}


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _gen_key(bits: int = 2048, key_type: str = "rsa"):
    """Generate an RSA or EC (P-256) private key. Used everywhere below."""
    if key_type == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=bits)
    if key_type == "ec":
        return ec.generate_private_key(ec.SECP256R1())
    raise ValueError(f"Unsupported key_type: {key_type!r}")


def _key_pem(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def _pub_pem(key) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _jwt_alg_for(key) -> str:
    """Return the JWT `alg` that matches the provided private key."""
    if isinstance(key, rsa.RSAPrivateKey):
        return "RS256"
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return "ES256"
    raise ValueError(f"Unsupported key type: {type(key).__name__}")


def init_broker_keys() -> tuple[str, str]:
    """
    Generate (or return) the ephemeral broker CA.
    Returns (private_key_pem, public_key_pem).
    Call once from conftest.py at "session" scope.
    """
    global _broker_ca_key, _broker_ca_cert

    if _broker_ca_key and _broker_ca_cert:
        return _key_pem(_broker_ca_key), _pub_pem(_broker_ca_key)

    now = _now()
    key = _gen_key(2048)  # 2048 is sufficient for tests
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test Broker CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Agent Trust Test"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(key, hashes.SHA256())
    )
    _broker_ca_key = key
    _broker_ca_cert = cert
    return _key_pem(key), _pub_pem(key)


def _get_org_ca(
    org_id: str, key_type: str = "rsa", path_length: int | None = 0,
) -> tuple:
    """Return (org_ca_key, org_ca_cert), generating them if necessary.

    ``path_length`` defaults to 0 (Org CA directly signs end-entity certs,
    classic BYOCA). Pass ``path_length=1`` for tests that need an
    intermediate CA below (SPIRE-style 3-level chain).
    """
    global _broker_ca_key, _broker_ca_cert

    cache_key = (org_id, key_type, path_length)
    if cache_key in _org_ca_cache:
        return _org_ca_cache[cache_key]

    if _broker_ca_key is None:
        init_broker_keys()

    now = _now()
    key = _gen_key(2048, key_type=key_type)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"{org_id} Test CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_id),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(_broker_ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        )
        .sign(_broker_ca_key, hashes.SHA256())
    )
    _org_ca_cache[cache_key] = (key, cert)
    return key, cert


def get_org_ca_pem(org_id: str, key_type: str = "rsa") -> str:
    """Return the PEM of the org's CA certificate (for upload to the broker)."""
    _, org_ca_cert = _get_org_ca(org_id, key_type=key_type)
    return org_ca_cert.public_bytes(serialization.Encoding.PEM).decode()


def make_agent_cert(
    agent_id: str,
    org_id: str,
    trust_domain: str | None = None,
    key_type: str = "rsa",
) -> tuple:
    """
    Generate (or return from cache) the agent certificate signed by the org CA.
    The cache guarantees the same agent always uses the same key within a test run,
    enabling message signature verification.

    trust_domain: if set, adds a SPIFFE URI SAN to the cert.
    key_type:     "rsa" (default) or "ec" (P-256). Must match the org CA key_type
                  for the cache — the org CA is signed by the broker CA (RSA), the
                  agent cert is signed by the org CA whose key_type determines the
                  signature algorithm.
    """
    cache_key = (agent_id, org_id, trust_domain, key_type)
    if cache_key in _agent_cert_cache:
        return _agent_cert_cache[cache_key]

    org_ca_key, org_ca_cert = _get_org_ca(org_id, key_type=key_type)

    now = _now()
    key = _gen_key(2048, key_type=key_type)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_id),
    ])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(org_ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if trust_domain is not None:
        # Add SPIFFE URI SAN: spiffe://trust-domain/org/agent-name
        _, agent_name = agent_id.split("::", 1)
        spiffe_id = f"spiffe://{trust_domain}/{org_id}/{agent_name}"
        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(spiffe_id),
            ]),
            critical=False,
        )
    cert = builder.sign(org_ca_key, hashes.SHA256())
    _agent_cert_cache[cache_key] = (key, cert)
    return key, cert


def get_org_ca_pem_for_chain(ca_org_id: str) -> str:
    """PEM of an Org CA with pathLenConstraint=1 — required for 3-level
    chain tests where the Org CA signs a SPIRE-style intermediate."""
    _, org_ca_cert = _get_org_ca(ca_org_id, path_length=1)
    return org_ca_cert.public_bytes(serialization.Encoding.PEM).decode()


def make_intermediate_ca(
    ca_org_id: str,
    name: str = "spire-intermediate",
    path_length: int | None = 0,
) -> tuple:
    """
    Generate an intermediate CA signed by the org CA (SPIRE-style).

    The Org CA used as issuer is fetched with path_length=1 so it is
    actually allowed to sign a CA below. path_length on the intermediate
    itself defaults to 0 (end-entity only).

    Returns (int_ca_key, int_ca_cert). Not cached — every call makes a new one.
    """
    org_ca_key, org_ca_cert = _get_org_ca(ca_org_id, path_length=1)
    now = _now()
    key = _gen_key(2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"{ca_org_id} {name}"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ca_org_id),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(org_ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(org_ca_key, hashes.SHA256())
    )
    return key, cert


def make_svid_with_chain(
    agent_name: str,
    ca_org_id: str,
    trust_domain: str,
    int_ca_key=None,
    int_ca_cert=None,
    spiffe_path: str | None = None,
) -> tuple:
    """
    Build an SVID signed by an intermediate (SPIRE-style 3-level chain).

    If ``int_ca_key``/``int_ca_cert`` are not provided, a fresh intermediate
    is minted via ``make_intermediate_ca(ca_org_id)``.

    Returns (svid_key, svid_cert, int_ca_cert, spiffe_id).
    """
    if int_ca_key is None or int_ca_cert is None:
        int_ca_key, int_ca_cert = make_intermediate_ca(ca_org_id)

    now = _now()
    key = _gen_key(2048)
    path = spiffe_path if spiffe_path is not None else agent_name
    spiffe_id = f"spiffe://{trust_domain}/{path}"
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(int_ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]),
            critical=True,
        )
        .sign(int_ca_key, hashes.SHA256())
    )
    return key, cert, int_ca_cert, spiffe_id


def make_svid_chain_assertion(
    agent_name: str,
    ca_org_id: str,
    trust_domain: str,
    int_ca_key=None,
    int_ca_cert=None,
    spiffe_path: str | None = None,
    extra_intermediates: list | None = None,
    sub_override: str | None = None,
    jti: str | None = "auto",
) -> tuple[str, str]:
    """
    Build a client_assertion with x5c = [SVID, intermediate, ...] for
    testing broker chain walk. ``extra_intermediates`` can inject
    additional cert(s) between the SVID and the real intermediate
    (e.g. for duplicate / wrong-order / cycle tests).

    Returns (assertion, spiffe_id).
    """
    svid_key, svid_cert, int_cert, spiffe_id = make_svid_with_chain(
        agent_name, ca_org_id, trust_domain,
        int_ca_key=int_ca_key, int_ca_cert=int_ca_cert,
        spiffe_path=spiffe_path,
    )
    chain = [svid_cert, int_cert]
    if extra_intermediates:
        # Insert after the leaf so the tampering is realistic.
        chain = [svid_cert] + list(extra_intermediates) + [int_cert]
    x5c = [
        base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode()
        for c in chain
    ]
    now = _now()
    sub = sub_override if sub_override is not None else spiffe_id
    payload = {
        "sub": sub, "iss": sub, "aud": "agent-trust-broker",
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(minutes=5)).timestamp()),
    }
    if jti == "auto":
        payload["jti"] = str(uuid.uuid4())
    elif jti is not None:
        payload["jti"] = jti
    return jwt.encode(
        payload, _key_pem(svid_key),
        algorithm=_jwt_alg_for(svid_key), headers={"x5c": x5c},
    ), spiffe_id


def make_svid_cert(
    agent_name: str,
    ca_org_id: str,
    trust_domain: str,
    spiffe_path: str | None = None,
    key_type: str = "rsa",
) -> tuple:
    """
    Produce an SPIRE-style SVID: cert signed by the org CA, EMPTY subject
    (no CN/O), identity encoded only in a SPIFFE URI SAN.

    ``ca_org_id``     identifies the org CA that signs the cert (controls chain).
    ``trust_domain``  goes into the SPIFFE URI authority.
    ``spiffe_path``   full path after the trust_domain (e.g. ``"workload/agent-a"``).
                      If None, defaults to ``agent_name`` as a single segment.
    """
    org_ca_key, org_ca_cert = _get_org_ca(ca_org_id, key_type=key_type)
    now = _now()
    key = _gen_key(2048, key_type=key_type)
    path = spiffe_path if spiffe_path is not None else agent_name
    spiffe_id = f"spiffe://{trust_domain}/{path}"
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))  # SVIDs carry no CN/O
        .issuer_name(org_ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]),
            critical=True,
        )
    )
    cert = builder.sign(org_ca_key, hashes.SHA256())
    return key, cert, spiffe_id


def make_svid_assertion(
    agent_name: str,
    ca_org_id: str,
    trust_domain: str,
    spiffe_path: str | None = None,
    sub_override: str | None = None,
    jti: str | None = "auto",
) -> tuple[str, str]:
    """Build a client_assertion JWT signed by an SVID-style cert.
    Returns (assertion, spiffe_id) — spiffe_id is useful for assertions in tests.
    """
    agent_key, agent_cert, spiffe_id = make_svid_cert(
        agent_name, ca_org_id, trust_domain, spiffe_path=spiffe_path,
    )
    cert_der = agent_cert.public_bytes(serialization.Encoding.DER)
    x5c = [base64.b64encode(cert_der).decode()]
    now = _now()
    sub = sub_override if sub_override is not None else spiffe_id
    payload = {
        "sub": sub,
        "iss": sub,
        "aud": "agent-trust-broker",
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(minutes=5)).timestamp()),
    }
    if jti == "auto":
        payload["jti"] = str(uuid.uuid4())
    elif jti is not None:
        payload["jti"] = jti
    return jwt.encode(
        payload, _key_pem(agent_key),
        algorithm=_jwt_alg_for(agent_key), headers={"x5c": x5c},
    ), spiffe_id


def make_agent_cert_alternate(
    agent_id: str,
    org_id: str,
    trust_domain: str | None = None,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """
    Generate a NEW agent certificate with a DIFFERENT RSA key for the same identity.
    Cached per (agent_id, org_id) — same alternate cert across calls within a test run.
    Used to test certificate thumbprint pinning (Rogue CA scenario).
    """
    cache_key = (agent_id, org_id)
    if cache_key in _agent_alt_cert_cache:
        return _agent_alt_cert_cache[cache_key]

    org_ca_key, org_ca_cert = _get_org_ca(org_id)

    now = _now()
    key = _gen_key(2048)  # Fresh key — different from the cached one
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_id),
    ])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(org_ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if trust_domain is not None:
        _, agent_name = agent_id.split("::", 1)
        spiffe_id = f"spiffe://{trust_domain}/{org_id}/{agent_name}"
        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(spiffe_id),
            ]),
            critical=False,
        )
    cert = builder.sign(org_ca_key, hashes.SHA256())
    _agent_alt_cert_cache[cache_key] = (key, cert)
    return key, cert


def make_assertion_alternate(
    agent_id: str,
    org_id: str,
    trust_domain: str | None = None,
) -> str:
    """
    Build a client_assertion with a DIFFERENT certificate than the cached one.
    Used for Rogue CA / thumbprint pinning tests.
    """
    agent_key, agent_cert = make_agent_cert_alternate(agent_id, org_id, trust_domain=trust_domain)
    cert_der = agent_cert.public_bytes(serialization.Encoding.DER)
    x5c = [base64.b64encode(cert_der).decode()]

    now = _now()
    payload = {
        "sub": agent_id,
        "iss": agent_id,
        "aud": "agent-trust-broker",
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(minutes=5)).timestamp()),
        "jti": str(uuid.uuid4()),
    }
    assertion = jwt.encode(payload, _key_pem(agent_key), algorithm="RS256", headers={"x5c": x5c})
    cert_pem = agent_cert.public_bytes(serialization.Encoding.PEM).decode()
    return assertion, cert_pem


def get_agent_cert_serial(agent_id: str, org_id: str, trust_domain: str | None = None) -> str:
    """Restituisce il serial number esadecimale del certificato agente (da cache)."""
    _, cert = make_agent_cert(agent_id, org_id, trust_domain=trust_domain)
    return format(cert.serial_number, 'x')


def get_agent_cert_not_after(agent_id: str, org_id: str, trust_domain: str | None = None):
    """Restituisce il not_valid_after del certificato agente (per test di revoca)."""
    _, cert = make_agent_cert(agent_id, org_id, trust_domain=trust_domain)
    try:
        return cert.not_valid_after_utc
    except AttributeError:
        return cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)


def get_agent_key_pem(agent_id: str, org_id: str, trust_domain: str | None = None) -> str:
    """Return the PEM of the agent's private key (same one used in make_assertion)."""
    key, _ = make_agent_cert(agent_id, org_id, trust_domain=trust_domain)
    return _key_pem(key)


def get_agent_pubkey_pem(agent_id: str, org_id: str, trust_domain: str | None = None) -> str:
    """Restituisce la chiave pubblica PEM dell'agente (dal certificato in cache)."""
    key, _ = make_agent_cert(agent_id, org_id, trust_domain=trust_domain)
    return _pub_pem(key)


def sign_message(
    agent_id: str,
    org_id: str,
    session_id: str,
    sender_agent_id: str,
    nonce: str,
    payload: dict,
    timestamp: int | None = None,
    trust_domain: str | None = None,
    client_seq: int | None = None,
) -> tuple[str, int]:
    """
    Sign a message with the agent's private key — for use in tests.
    Uses the same key used in make_assertion (thanks to the cache).
    Returns (signature, timestamp) so callers can include timestamp in the envelope.
    """
    import time as _time
    from app.auth.message_signer import sign_message as _sign
    if timestamp is None:
        timestamp = int(_time.time())
    key_pem = get_agent_key_pem(agent_id, org_id, trust_domain=trust_domain)
    return _sign(key_pem, session_id, sender_agent_id, nonce, timestamp, payload, client_seq=client_seq), timestamp


def make_encrypted_envelope(
    sender_agent_id: str,
    sender_org_id: str,
    recipient_agent_id: str,
    recipient_org_id: str,
    session_id: str,
    nonce: str,
    payload: dict,
    client_seq: int | None = None,
) -> dict:
    """
    Costruisce un envelope E2E cifrato completo per i test.

    1. Firma interna sul plaintext (non-repudiation per il destinatario)
    2. Cifra {payload, inner_sig} con la pubkey del destinatario
    3. Firma esterna sul ciphertext (integrità trasporto per il broker)
    """
    import time as _time
    from app.e2e_crypto import encrypt_for_agent

    timestamp = int(_time.time())
    inner_sig, _ = sign_message(sender_agent_id, sender_org_id, session_id, sender_agent_id,
                                nonce, payload, timestamp, client_seq=client_seq)
    recipient_pubkey = get_agent_pubkey_pem(recipient_agent_id, recipient_org_id)
    cipher_blob = encrypt_for_agent(recipient_pubkey, payload, inner_sig, session_id,
                                    sender_agent_id, client_seq=client_seq)
    outer_sig, _ = sign_message(sender_agent_id, sender_org_id, session_id, sender_agent_id,
                                nonce, cipher_blob, timestamp, client_seq=client_seq)

    envelope = {
        "session_id":      session_id,
        "sender_agent_id": sender_agent_id,
        "payload":         cipher_blob,
        "nonce":           nonce,
        "timestamp":       timestamp,
        "signature":       outer_sig,
    }
    if client_seq is not None:
        envelope["client_seq"] = client_seq
    return envelope


# ─────────────────────────────────────────────────────────────────────────────
# DPoP test helpers
# ─────────────────────────────────────────────────────────────────────────────

def make_dpop_key_pair() -> tuple[ec.EllipticCurvePrivateKey, dict]:
    """
    Generate an ephemeral EC P-256 key pair for DPoP proofs.
    Returns (private_key, public_jwk_dict).
    """
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    nums = pub.public_numbers()
    x = base64.urlsafe_b64encode(nums.x.to_bytes(32, "big")).rstrip(b"=").decode()
    y = base64.urlsafe_b64encode(nums.y.to_bytes(32, "big")).rstrip(b"=").decode()
    jwk = {"kty": "EC", "crv": "P-256", "x": x, "y": y}
    return priv, jwk


def make_dpop_proof(
    privkey: ec.EllipticCurvePrivateKey,
    jwk: dict,
    method: str,
    url: str,
    access_token: str | None = None,
    jti: str | None = None,
    iat_offset: int = 0,
    nonce: str | None = None,
) -> str:
    """
    Generate a DPoP proof JWT signed with the given EC private key.

    jti:        custom JTI (for replay tests); auto-generated if None
    iat_offset: seconds to add to current time (negative = expired, for freshness tests)
    """
    priv_pem = privkey.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()

    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + iat_offset
    claims: dict = {
        "jti": jti if jti is not None else str(uuid.uuid4()),
        "htm": method.upper(),
        "htu": url,
        "iat": now,
    }
    if access_token is not None:
        claims["ath"] = (
            base64.urlsafe_b64encode(
                hashlib.sha256(access_token.encode()).digest()
            ).rstrip(b"=").decode()
        )
    if nonce is not None:
        claims["nonce"] = nonce

    return jwt.encode(
        claims,
        priv_pem,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": jwk},
    )


class DPoPHelper:
    """
    Per-test DPoP key pair + convenience methods.

    Usage in tests:
        token = await dpop.get_token(client, "org::agent", "org")
        headers = dpop.headers("GET", "/v1/broker/sessions", token)
        resp = await client.get("/v1/broker/sessions", headers=headers)
    """

    # Base URL used by the test AsyncClient (matches conftest base_url="http://test")
    BASE_URL = "http://test"

    def __init__(self) -> None:
        self._privkey, self._jwk = make_dpop_key_pair()
        # Pre-prime with server nonce so proofs are accepted immediately
        from app.auth.dpop import get_current_dpop_nonce
        self._nonce: str | None = get_current_dpop_nonce()

    def _update_nonce(self, resp) -> None:
        nonce = resp.headers.get("dpop-nonce")
        if nonce:
            self._nonce = nonce

    def proof(
        self,
        method: str,
        path_or_url: str,
        access_token: str | None = None,
        jti: str | None = None,
        iat_offset: int = 0,
        nonce: str | None = "auto",
    ) -> str:
        """Build a DPoP proof. path_or_url can be '/auth/token' or a full URL."""
        url = (
            path_or_url
            if "://" in path_or_url
            else self.BASE_URL + path_or_url
        )
        actual_nonce = self._nonce if nonce == "auto" else nonce
        return make_dpop_proof(
            self._privkey, self._jwk, method, url,
            access_token=access_token, jti=jti, iat_offset=iat_offset,
            nonce=actual_nonce,
        )

    def headers(self, method: str, path_or_url: str, access_token: str) -> dict:
        """Return Authorization + DPoP headers for an authenticated request."""
        return {
            "Authorization": f"DPoP {access_token}",
            "DPoP": self.proof(method, path_or_url, access_token),
        }

    async def get_token(
        self, client, agent_id: str, org_id: str, trust_domain: str | None = None
    ) -> str:
        """Authenticate agent and return a DPoP-bound access token.
        Handles the server nonce flow (RFC 9449 §8): first attempt may return
        401 with DPoP-Nonce header, then we retry with the nonce."""
        assertion = make_assertion(agent_id, org_id, trust_domain=trust_domain)
        dpop_proof = self.proof("POST", "/v1/auth/token")
        resp = await client.post(
            "/v1/auth/token",
            json={"client_assertion": assertion},
            headers={"DPoP": dpop_proof},
        )
        # Handle nonce requirement — retry once
        if resp.status_code == 401 and "use_dpop_nonce" in resp.text:
            self._update_nonce(resp)
            assertion = make_assertion(agent_id, org_id, trust_domain=trust_domain)
            dpop_proof = self.proof("POST", "/v1/auth/token")
            resp = await client.post(
                "/v1/auth/token",
                json={"client_assertion": assertion},
                headers={"DPoP": dpop_proof},
            )
        self._update_nonce(resp)
        assert resp.status_code == 200, f"Login failed: {resp.text}"
        return resp.json()["access_token"]


def make_assertion(
    agent_id: str,
    org_id: str,
    jti: str | None = "auto",
    trust_domain: str | None = None,
    key_type: str = "rsa",
) -> str:
    """
    Generate a valid client_assertion JWT for agent_id/org_id.
    The certificate is signed by the org CA (same instance for the entire test run).

    jti="auto" (default)  → generates a random UUID
    jti=<string>          → uses the provided value (for replay tests)
    jti=None              → omits the jti field from the payload (for validation tests)
    trust_domain          → if provided, the cert will include a SPIFFE SAN URI
    key_type              → "rsa" (default) or "ec" — drives RS256 / ES256 JWT alg
    """
    agent_key, agent_cert = make_agent_cert(
        agent_id, org_id, trust_domain=trust_domain, key_type=key_type,
    )

    cert_der = agent_cert.public_bytes(serialization.Encoding.DER)
    x5c = [base64.b64encode(cert_der).decode()]

    now = _now()
    payload = {
        "sub": agent_id,
        "iss": agent_id,
        "aud": "agent-trust-broker",
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(minutes=5)).timestamp()),
    }
    if jti == "auto":
        payload["jti"] = str(uuid.uuid4())
    elif jti is not None:
        payload["jti"] = jti
    # jti=None → not included in the payload

    return jwt.encode(
        payload, _key_pem(agent_key),
        algorithm=_jwt_alg_for(agent_key), headers={"x5c": x5c},
    )
