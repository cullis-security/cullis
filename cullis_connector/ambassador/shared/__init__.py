"""Cullis Frontdesk shared mode (ADR-021 PR4b).

Sub-package activated when ``AMBASSADOR_MODE=shared`` (default
``single``). Adds:

  - ``cookie``        HMAC-signed session cookie helpers
  - ``proxy_trust``   ``X-Forwarded-User`` allowlist + extraction
  - ``credentials``   per-user (cert + KMS handle) LRU+TTL cache
  - ``provisioning``  KMS create_keypair → CSR → Mastio sign → cache
  - ``router``        FastAPI router for the multi-tenant surface

Single mode (``cullis_connector/ambassador/router.py``) is unchanged.
"""
