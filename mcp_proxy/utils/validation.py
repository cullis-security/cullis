"""Strict base64url decoder — vendored for Mastio (audit S8 / F-C-3).

``mcp_proxy`` has no runtime dependency on ``app/``, so the canonical
implementation from ``app.utils.validation.strict_b64url_decode`` is
vendored here verbatim. Behavior must remain identical to the canonical copy;
parity is verified by ``tests/test_b64url_decoder_parity.py``.

All base64url decoding within ``mcp_proxy/`` should import from here rather
than inlining its own copy, so any future hardening applies in one place.

Do NOT relax or extend this implementation without a corresponding change to
``app/utils/validation.strict_b64url_decode`` and ``cullis_sdk/_b64url.py``.
"""
from __future__ import annotations

import base64
import re

# url-safe base64 alphabet (RFC 4648 §5). Excludes padding — handled separately.
_B64URL_ALPHABET_RE = re.compile(r"^[A-Za-z0-9_-]*$")


class B64urlError(ValueError):
    """Raised when a base64url string is malformed or non-canonical."""


def strict_b64url_decode(s: str | bytes) -> bytes:
    """Decode a base64url string, rejecting non-canonical encodings.

    Accepts ``s`` with OR without trailing ``=`` padding (the codebase
    convention — TS SDK omits padding, some tests include it). Rejects:

      * Non-alphabet characters (whitespace, ``+``, ``/``, ``\\n``, etc.)
      * Excess padding (e.g. ``AAAA===`` — valid for stdlib, rejected here)
      * Impossible lengths (``len(s.rstrip("=")) % 4 == 1``)
      * Trailing "garbage bits" in partial-quantum inputs — Python's stdlib
        silently zeroes the unused low-order bits of the last char, which
        means ``AAAA`` and ``AAAB`` decode to the same 3 bytes.

    On any violation raises ``B64urlError`` (a ``ValueError`` subclass) so
    callers that wrap in ``except Exception`` continue to work.
    """
    if isinstance(s, bytes):
        try:
            s = s.decode("ascii")
        except UnicodeDecodeError as exc:
            raise B64urlError("base64url input is not ASCII") from exc
    if not isinstance(s, str):
        raise B64urlError(
            f"base64url input must be str/bytes, got {type(s).__name__}"
        )

    # Strip trailing padding (tolerant). ``AAAA==`` and ``AAAA====`` both
    # strip to ``AAAA`` — the over-padded case is caught when we re-pad
    # below (stdlib silently ignores excess padding; we force-match).
    stripped = s.rstrip("=")

    # Reject non-alphabet content — no whitespace, no vanilla +/.
    if not _B64URL_ALPHABET_RE.fullmatch(stripped):
        raise B64urlError("base64url contains non-url-safe characters")

    # Length mod 4 == 1 is impossible in base64 (1 char = 6 bits, no way
    # to complete a byte). Raise explicitly — stdlib would raise too but
    # via the less-specific ``binascii.Error``.
    rem = len(stripped) % 4
    if rem == 1:
        raise B64urlError("base64url length is not valid (length % 4 == 1)")

    # Re-pad to canonical form and decode.
    padded = stripped + ("=" * ((4 - rem) % 4))
    try:
        decoded = base64.urlsafe_b64decode(padded)
    except Exception as exc:
        raise B64urlError(f"base64url decode failed: {exc}") from exc

    # Re-encode and compare to catch "garbage bits" in partial-quantum
    # inputs. stdlib silently drops the low-order bits of the last char
    # when they aren't consumed — that means two different input strings
    # can decode to the same bytes, which breaks canonicalization (JKT).
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != stripped:
        raise B64urlError(
            "base64url contains non-canonical trailing bits — "
            "decoded bytes do not round-trip to the input"
        )

    return decoded


def canonicalize_b64url(s: str) -> str:
    """Round-trip a base64url string through strict decode -> no-pad encode.

    Used to normalize JWK coordinates before thumbprint hashing. Two wire
    encodings of the same key collapse to the same canonical string.
    """
    decoded = strict_b64url_decode(s)
    return base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")


__all__ = ["B64urlError", "canonicalize_b64url", "strict_b64url_decode"]
