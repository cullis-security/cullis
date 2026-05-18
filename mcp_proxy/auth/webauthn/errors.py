"""Typed exceptions for the WebAuthn helper layer.

Keeping the exceptions local makes the API surface stable when the
underlying ``webauthn`` library bumps a major version (its own exception
classes have moved between 1.x and 2.x).
"""
from __future__ import annotations


class WebAuthnError(Exception):
    """Base class for every error raised by ``mcp_proxy.auth.webauthn``."""


class WebAuthnLibraryMissingError(WebAuthnError):
    """The optional ``webauthn`` extra is not installed.

    Raised when a code path needs the library at runtime and the import
    fails. ``validate_config`` catches this at startup when enforcement
    is ``required`` so the message surfaces before a user tries to log in.
    """


class WebAuthnVerificationFailedError(WebAuthnError):
    """Verification of an assertion or attestation did not succeed.

    The string passed to ``__init__`` is operator-facing — it appears in
    audit chain entries and dashboard error pages. Avoid leaking
    challenge bytes, signature material or other secrets in the message.
    """
