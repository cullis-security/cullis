"""ADR-033 Phase 2 — WebAuthn user assertion binding.

This sub-package wraps the third-party ``webauthn`` library (py_webauthn)
with the surface Cullis Mastio needs:

* :mod:`registration` — generate ``publicKeyCredentialCreationOptions``
  and verify the resulting ``AttestationObject`` returned by the browser.
* :mod:`authentication` — generate ``publicKeyCredentialRequestOptions``
  and verify the assertion presented at session emission.
* :mod:`storage` — persistence helpers for ``user_webauthn_credentials``
  (one row per registered authenticator) and challenge bookkeeping.

The library is imported lazily inside each helper so a Mastio running
``MCP_PROXY_WEBAUTHN_ENFORCEMENT=off`` (or unset) keeps booting even
when the optional ``[webauthn]`` extra is absent. ``validate_config``
catches the missing package up front when enforcement is ``required``.
"""

from mcp_proxy.auth.webauthn.errors import (
    WebAuthnError,
    WebAuthnLibraryMissingError,
    WebAuthnVerificationFailedError,
)

__all__ = [
    "WebAuthnError",
    "WebAuthnLibraryMissingError",
    "WebAuthnVerificationFailedError",
]
