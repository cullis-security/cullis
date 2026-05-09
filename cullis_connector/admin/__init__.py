"""Connector admin API package — ADR-025.

Provisioning endpoints for local user accounts (Phase 1) plus the
read-only audit log viewer (Phase 4). Mounted by
``cullis_connector.web.build_app`` when ``AUTH_MODE=local`` (the
default for Frontdesk shared mode without a corporate IdP).
"""
