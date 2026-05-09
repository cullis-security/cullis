"""Connector admin API package — ADR-025 Phase 1.

Provisioning endpoints for local user accounts. Only mounted by
``cullis_connector.web.build_app`` when ``AUTH_MODE=local`` (the
default for Frontdesk shared mode without a corporate IdP).
"""
