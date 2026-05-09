"""Connector auth surface — ADR-025 Phase 2.

Holds the FastAPI routers that drive end-user authentication flows
when ``AUTH_MODE=local`` (the Frontdesk SMB default). Distinct from
``cullis_connector.admin`` (which hosts admin-only provisioning APIs)
and from ``cullis_connector.ambassador.shared`` (which handles the
multi-tenant SSO flow when ``AMBASSADOR_MODE=shared``).
"""
