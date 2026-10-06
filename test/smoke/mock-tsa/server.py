"""Mock RFC 3161 TSA + OpenAI-compatible chat-completions stub.

Listens on two ports inside the smoke container:

  :2560  POST /tsr   — RFC 3161 TimeStampReq → signed TimeStampResp
         GET  /health — liveness probe used by compose healthcheck
  :2561  POST /v1/chat/completions — OpenAI shape stub returning a
         fixed completion the chat scenario asserts on.

The TSA mints a self-issued ECDSA CA at boot, signs a TSA leaf cert
under it, then signs every incoming request's messageImprint with the
TSA leaf. The resulting TimeStampToken parses cleanly under the
in-tree verifier (mcp_proxy/audit/tsa_client.py) and under the
standalone cullis-audit-verify.py — both call into asn1crypto.tsp on
the same shape.

Why not use the real digicert TSA in smoke: smoke runs offline. The
mock is good enough to exercise the real anchor watcher code path
end-to-end without bringing in an internet dependency.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone
from typing import Final

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
import asn1crypto.tsp as tsp
import asn1crypto.cms as cms
import asn1crypto.algos as algos
import asn1crypto.core as core
import asn1crypto.x509 as asn1_x509


logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format="[mock-tsa] %(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("mock-tsa")


# RFC 3161 content types
_REQ_CT: Final = b"application/timestamp-query"
_REPLY_CT: Final = b"application/timestamp-reply"


# ── PKI bootstrap (in-memory, regenerated each container start) ─────────────

def _build_pki() -> tuple[
    ec.EllipticCurvePrivateKey, x509.Certificate,
    ec.EllipticCurvePrivateKey, x509.Certificate,
]:
    """Mint a self-issued CA + a TSA leaf cert under it. Both ECDSA P-256.

    Returns (ca_key, ca_cert, tsa_key, tsa_cert). All ephemeral —
    the smoke harness is single-shot so durability of the PKI is
    not a concern.
    """
    ca_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Cullis Smoke Mock TSA CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Cullis Smoke"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    tsa_key = ec.generate_private_key(ec.SECP256R1())
    tsa_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Cullis Smoke Mock TSA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Cullis Smoke"),
    ])
    tsa_cert = (
        x509.CertificateBuilder()
        .subject_name(tsa_subject)
        .issuer_name(ca_subject)
        .public_key(tsa_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    log.info("PKI ready: CA + TSA leaf minted (ECDSA P-256, self-issued)")
    return ca_key, ca_cert, tsa_key, tsa_cert


_CA_KEY, _CA_CERT, _TSA_KEY, _TSA_CERT = _build_pki()
_TSA_CERT_DER = _TSA_CERT.public_bytes(serialization.Encoding.DER)
_TSA_CERT_ASN1 = asn1_x509.Certificate.load(_TSA_CERT_DER)


# ── TimeStampToken builder ──────────────────────────────────────────────────

def _build_tsr(req_der: bytes) -> bytes:
    """Parse the request, build a signed TimeStampResp, return DER bytes.

    The response is a TimeStampResp{status: granted, time_stamp_token:
    <SignedData containing TSTInfo>}. We sign the TSTInfo's DER encoding
    with the TSA leaf's ECDSA-SHA256 key and embed the leaf cert in
    SignedData.certificates so verifiers can walk the chain.
    """
    req = tsp.TimeStampReq.load(req_der)
    imprint = req["message_imprint"]
    nonce_val = req["nonce"].native if req["nonce"] is not None else None

    # TSTInfo — the actual timestamp payload.
    tst_info = tsp.TSTInfo({
        "version": "v1",
        "policy": "1.2.3.4.5",  # arbitrary policy OID; verifier ignores
        "message_imprint": imprint,
        "serial_number": int.from_bytes(secrets.token_bytes(8), "big"),
        "gen_time": datetime.now(timezone.utc),
        "accuracy": tsp.Accuracy({"seconds": 1}),
        "ordering": False,
        "nonce": nonce_val,
        "tsa": tsp.GeneralName(
            name="directory_name", value=_TSA_CERT_ASN1["tbs_certificate"]["subject"],
        ),
    })
    tst_info_der = tst_info.dump()

    # Sign the TSTInfo DER with the TSA leaf key.
    signature = _TSA_KEY.sign(tst_info_der, ec.ECDSA(hashes.SHA256()))

    signer_info = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier(
            name="issuer_and_serial_number",
            value=cms.IssuerAndSerialNumber({
                "issuer": _TSA_CERT_ASN1["tbs_certificate"]["issuer"],
                "serial_number": _TSA_CERT_ASN1["tbs_certificate"]["serial_number"],
            }),
        ),
        "digest_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
        "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": "sha256_ecdsa"}),
        "signature": signature,
    })

    signed_data = cms.SignedData({
        "version": "v3",
        "digest_algorithms": [algos.DigestAlgorithm({"algorithm": "sha256"})],
        "encap_content_info": cms.EncapsulatedContentInfo({
            "content_type": "tst_info",
            "content": core.ParsableOctetString(tst_info_der),
        }),
        "certificates": [cms.CertificateChoices(name="certificate", value=_TSA_CERT_ASN1)],
        "signer_infos": [signer_info],
    })

    token = cms.ContentInfo({
        "content_type": "signed_data",
        "content": signed_data,
    })

    resp = tsp.TimeStampResp({
        "status": tsp.PKIStatusInfo({"status": "granted"}),
        "time_stamp_token": token,
    })
    return resp.dump()


# ── Minimal HTTP server over asyncio (no FastAPI dep in mock image) ─────────

async def _read_http_request(reader: asyncio.StreamReader) -> tuple[str, str, dict, bytes]:
    """Parse a single HTTP request. Returns (method, path, headers, body).

    Bare minimum — no chunked transfer, no keepalive. Each connection
    serves one request and closes.
    """
    request_line = await reader.readuntil(b"\r\n")
    parts = request_line.decode("latin-1").rstrip("\r\n").split(" ")
    if len(parts) < 2:
        raise ValueError(f"malformed request line: {request_line!r}")
    method, path = parts[0], parts[1]

    headers: dict[str, str] = {}
    while True:
        line = await reader.readuntil(b"\r\n")
        if line == b"\r\n":
            break
        name, _, value = line.decode("latin-1").rstrip("\r\n").partition(":")
        headers[name.strip().lower()] = value.strip()

    length = int(headers.get("content-length", "0"))
    body = await reader.readexactly(length) if length > 0 else b""
    return method, path, headers, body


def _http_response(
    status: str, body: bytes, content_type: bytes = b"text/plain",
) -> bytes:
    return (
        f"HTTP/1.1 {status}\r\n".encode("ascii")
        + b"Content-Type: " + content_type + b"\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"Connection: close\r\n\r\n"
        + body
    )


async def _handle_tsa(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
) -> None:
    try:
        method, path, _headers, body = await _read_http_request(reader)
        if method == "GET" and path == "/health":
            writer.write(_http_response("200 OK", b"ok\n"))
        elif method == "POST" and path == "/tsr":
            try:
                tsr = _build_tsr(body)
            except Exception as exc:  # noqa: BLE001
                log.warning("tsa: build failure: %s", exc)
                writer.write(_http_response(
                    "400 Bad Request", f"tsa build error: {exc}".encode(),
                ))
            else:
                writer.write(_http_response("200 OK", tsr, _REPLY_CT))
        else:
            writer.write(_http_response("404 Not Found", b"not found\n"))
    except Exception as exc:  # noqa: BLE001
        log.warning("tsa: connection handler error: %s", exc)
    finally:
        with contextlib_suppress(Exception):
            await writer.drain()
        writer.close()


TOOL_COUNTS: dict[str, int] = {}


async def _handle_chat(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
) -> None:
    try:
        method, path, _headers, body = await _read_http_request(reader)
        if method == "GET" and path == "/health":
            writer.write(_http_response("200 OK", b"ok\n"))
            return
        if method == "GET" and path == "/tool-counts":
            writer.write(_http_response("200 OK", json.dumps(TOOL_COUNTS).encode(), b"application/json"))
            return
        if method == "POST" and path == "/mcp":
            req = json.loads(body)
            if req.get("method") == "tools/list":
                result = {"tools": [{"name": n, "inputSchema": {"type": "object"}}
                                    for n in ("open_ticket", "issue_refund")]}
            elif req.get("method") == "tools/call":
                name = req["params"]["name"]
                if name not in ("open_ticket", "issue_refund"):
                    raise ValueError("Unknown fixture tool")
                TOOL_COUNTS[name] = TOOL_COUNTS.get(name, 0) + 1
                result = {"content": [{"type": "text", "text": "synthetic operation completed"}], "isError": False}
            else:
                raise ValueError("Unknown fixture method")
            writer.write(_http_response("200 OK", json.dumps({
                "jsonrpc": "2.0", "id": req.get("id"), "result": result,
            }).encode(), b"application/json"))
            return
        if method == "POST" and path in (
            "/v1/chat/completions", "/chat/completions",
        ):
            # OpenAI-compatible shape — served for the legacy ``portkey``
            # backend and the native OpenAI adapter (AsyncOpenAI posts
            # here). Parse just enough to echo the model name back.
            try:
                req = json.loads(body or b"{}")
                model = req.get("model", "unknown")
            except Exception:  # noqa: BLE001
                model = "unknown"
            payload = {
                "id": "chatcmpl-smoke-" + secrets.token_hex(6),
                "object": "chat.completion",
                "created": int(datetime.now(timezone.utc).timestamp()),
                "model": model,
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "smoke-mock-ok",
                    },
                    "finish_reason": "stop",
                }],
                "usage": {
                    "prompt_tokens": 1,
                    "completion_tokens": 1,
                    "total_tokens": 2,
                },
            }
            writer.write(_http_response(
                "200 OK", json.dumps(payload).encode(),
                b"application/json",
            ))
            return
        if method == "POST" and path in ("/v1/messages", "/messages"):
            # Anthropic Messages shape — served for the PRODUCT DEFAULT
            # cullis_native backend. anthropic.AsyncAnthropic posts here
            # (base_url + /v1/messages); the response must satisfy the
            # SDK's Message model so AnthropicAdapter.translate_response
            # can map it to the OpenAI shape the scenario asserts on
            # (choices[0].message.content == "smoke-mock-ok").
            try:
                req = json.loads(body or b"{}")
                model = req.get("model", "unknown")
            except Exception:  # noqa: BLE001
                model = "unknown"
            payload = {
                "id": "msg_smoke_" + secrets.token_hex(6),
                "type": "message",
                "role": "assistant",
                "model": model,
                "content": [{"type": "text", "text": "smoke-mock-ok"}],
                "stop_reason": "end_turn",
                "stop_sequence": None,
                "usage": {"input_tokens": 1, "output_tokens": 1},
            }
            writer.write(_http_response(
                "200 OK", json.dumps(payload).encode(),
                b"application/json",
            ))
            return
        writer.write(_http_response("404 Not Found", b"not found\n"))
    except Exception as exc:  # noqa: BLE001
        log.warning("chat: connection handler error: %s", exc)
    finally:
        with contextlib_suppress(Exception):
            await writer.drain()
        writer.close()


class contextlib_suppress:
    """Minimal contextlib.suppress lookalike to avoid an import."""
    def __init__(self, *excs: type[BaseException]) -> None:
        self._excs = excs
    def __enter__(self) -> None:
        return None
    def __exit__(self, exc_type, exc, tb) -> bool:  # noqa: D401
        return exc_type is not None and issubclass(exc_type, self._excs)
    async def __aenter__(self) -> None:
        return None
    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return exc_type is not None and issubclass(exc_type, self._excs)


async def _main() -> None:
    tsa_port = int(os.environ.get("MOCK_TSA_PORT", "2560"))
    chat_port = int(os.environ.get("MOCK_CHAT_PORT", "2561"))

    tsa_srv = await asyncio.start_server(_handle_tsa, "0.0.0.0", tsa_port)
    chat_srv = await asyncio.start_server(_handle_chat, "0.0.0.0", chat_port)
    log.info("listening — TSA on :%d, chat on :%d", tsa_port, chat_port)
    async with tsa_srv, chat_srv:
        await asyncio.gather(tsa_srv.serve_forever(), chat_srv.serve_forever())


if __name__ == "__main__":
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        log.info("shutting down")
