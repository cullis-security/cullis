"""Connector admin-API auth dependency.

Mirrors ``mcp_proxy/admin/users.py``'s ``X-Admin-Secret`` contract so
operators only have to learn one shape: every admin route on the
Cullis stack reads the same header, compared in constant time. The
secret value lives in the ``CULLIS_CONNECTOR_ADMIN_SECRET`` env var
and is intentionally distinct from the Mastio admin secret — the two
control planes are separate, and a leaked Mastio secret should not
grant local user provisioning on the Connector.

Returns 403 (not 401) on miss/mismatch to match the existing Mastio
admin endpoints.
"""
from __future__ import annotations

import hmac
import os

from fastapi import Header, HTTPException, status

ADMIN_SECRET_ENV = "CULLIS_CONNECTOR_ADMIN_SECRET"


def _require_admin_secret(
    x_admin_secret: str = Header(..., alias="X-Admin-Secret"),
) -> None:
    """FastAPI dependency. Raises 403 unless the header matches the env."""
    expected = os.environ.get(ADMIN_SECRET_ENV, "")
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="admin secret not configured on this Connector",
        )
    if not hmac.compare_digest(x_admin_secret or "", expected):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="invalid admin secret",
        )
