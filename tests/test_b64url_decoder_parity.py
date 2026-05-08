"""Parity test for the three vendored strict base64url decoders (audit H4/H5/S8).

Verifies that all three implementations behave identically on every input in
the test matrix:

  1. ``app.utils.validation.strict_b64url_decode`` — canonical (Court)
  2. ``mcp_proxy.utils.validation.strict_b64url_decode`` — vendored for Mastio (S8)
  3. ``cullis_sdk._b64url.strict_b64url_decode`` — vendored for SDK (H5)

All three must:
  * Accept the same valid inputs and return identical bytes.
  * Raise ``ValueError`` (or a subclass) on every invalid input.
  * Raise on non-canonical trailing-bit inputs (the core security property).

The test does NOT assert on the exact exception message, only on the type, so
minor wording differences between implementations do not cause false failures.
"""
from __future__ import annotations

import base64
import pytest

# ── import all three implementations ─────────────────────────────────────────

from app.utils.validation import strict_b64url_decode as _court_decode
from mcp_proxy.utils.validation import strict_b64url_decode as _mastio_decode
from cullis_sdk._b64url import strict_b64url_decode as _sdk_decode

_IMPLS = [
    ("court", _court_decode),
    ("mastio", _mastio_decode),
    ("sdk", _sdk_decode),
]


# ── helpers ───────────────────────────────────────────────────────────────────

def _b64url(b: bytes) -> str:
    """Canonical no-pad base64url encode, used to build valid test inputs."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


# ── valid input matrix ────────────────────────────────────────────────────────

_VALID_CASES: list[tuple[str, bytes, str]] = [
    # label, expected_bytes, input_string
    ("empty", b"", ""),
    ("1byte", b"\x00", _b64url(b"\x00")),
    ("2bytes", b"\x00\x01", _b64url(b"\x00\x01")),
    ("3bytes", b"\x00\x01\x02", _b64url(b"\x00\x01\x02")),
    ("4bytes", b"\xff\xfe\xfd\xfc", _b64url(b"\xff\xfe\xfd\xfc")),
    # With padding appended — all three must tolerate padding
    ("padded_2mod4", b"\x00\x01\x02", _b64url(b"\x00\x01\x02") + "="),
    ("padded_1mod4", b"\x00", _b64url(b"\x00") + "=="),
    # 32 bytes (EC P-256 coordinate size, common in JWK)
    ("ec_coord_32", bytes(range(32)), _b64url(bytes(range(32)))),
    # bytes that encode to url-safe chars (contain - and _)
    ("url_safe_chars", b"\xfb\xef", _b64url(b"\xfb\xef")),  # encodes to "-+8="
    # bytes input — all three accept bytes as well as str
    ("bytes_input", b"\xca\xfe", _b64url(b"\xca\xfe")),
]


@pytest.mark.parametrize("label,expected,inp", _VALID_CASES, ids=[c[0] for c in _VALID_CASES])
@pytest.mark.parametrize("impl_name,impl", _IMPLS, ids=[i[0] for i in _IMPLS])
def test_valid_inputs(impl_name: str, impl, label: str, expected: bytes, inp: str) -> None:
    """All implementations decode valid inputs to identical bytes."""
    got = impl(inp)
    assert got == expected, (
        f"[{impl_name}] {label!r}: expected {expected!r}, got {got!r}"
    )


@pytest.mark.parametrize("impl_name,impl", _IMPLS, ids=[i[0] for i in _IMPLS])
def test_bytes_input_accepted(impl_name: str, impl) -> None:
    """All implementations accept bytes input (not just str)."""
    raw = b"AQID"  # canonical b64url for b"\x01\x02\x03"
    assert impl(raw) == b"\x01\x02\x03"


# ── invalid input matrix ──────────────────────────────────────────────────────

_INVALID_CASES: list[tuple[str, str]] = [
    # label, input_string
    # Non-url-safe characters
    ("vanilla_plus", "AA+A"),
    ("vanilla_slash", "AA/A"),
    ("whitespace", "AA A"),
    ("newline", "AA\nAA"),
    ("tab", "AA\tAA"),
    # Impossible length (len % 4 == 1)
    ("bad_length_mod4_eq1", "A"),
    ("bad_length_mod4_eq1_long", "AAAAA"),
    # Garbage trailing bits — the critical security property.
    # Base64 encodes 3 bytes per 4 chars. When you have 2 chars (12 bits)
    # the last 4 bits must be zero. 'AB' → 0x00 0x10, re-encoded → 'AB'.
    # 'AC' → 0x00 0x20, re-encoded → 'AC' ≠ 'AB'. But stdlib decodes
    # both to b'\x00' with a garbage low nibble silently discarded.
    # We must reject 'AC', 'AD', …, 'AP' when 'AB' is the canonical form.
    ("garbage_bits_2char", "AC"),   # 'AB' is canonical for b'\x00'; 'AC' is not
    ("garbage_bits_3char", "AAB"),  # 'AAA' is canonical for b'\x00\x00'; 'AAB' is not
]


@pytest.mark.parametrize("label,inp", _INVALID_CASES, ids=[c[0] for c in _INVALID_CASES])
@pytest.mark.parametrize("impl_name,impl", _IMPLS, ids=[i[0] for i in _IMPLS])
def test_invalid_inputs_raise(impl_name: str, impl, label: str, inp: str) -> None:
    """All implementations raise ValueError (or subclass) on invalid inputs."""
    with pytest.raises(ValueError, match=""):
        impl(inp)
        pytest.fail(f"[{impl_name}] {label!r}: expected ValueError, but returned without error")


# ── cross-implementation agreement ───────────────────────────────────────────

_AGREEMENT_VALID = [
    _b64url(bytes(range(i, i + 10))) for i in range(0, 40, 10)
]
_AGREEMENT_INVALID = [
    "AA+A", "A", "AAAAB", "AA\nAA", "AC", "AAB",
]


@pytest.mark.parametrize("inp", _AGREEMENT_VALID)
def test_cross_impl_agreement_valid(inp: str) -> None:
    """All three implementations return identical bytes for valid inputs."""
    results = {name: impl(inp) for name, impl in _IMPLS}
    values = list(results.values())
    assert all(v == values[0] for v in values), (
        f"Cross-impl disagreement for {inp!r}: {results}"
    )


@pytest.mark.parametrize("inp", _AGREEMENT_INVALID)
def test_cross_impl_agreement_invalid(inp: str) -> None:
    """All three implementations raise on the same invalid inputs."""
    raised = {}
    for name, impl in _IMPLS:
        try:
            result = impl(inp)
            raised[name] = f"returned {result!r}"
        except ValueError:
            raised[name] = "raised"
        except Exception as exc:
            raised[name] = f"raised {type(exc).__name__}"

    unanimous = all(v == "raised" for v in raised.values())
    assert unanimous, (
        f"Cross-impl disagreement on invalid input {inp!r}: {raised}"
    )
