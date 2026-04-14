"""ADR-001 Phase 3 — local mini-broker surface for intra-org traffic.

This subpackage hosts the proxy's in-process session + message machinery
that mirrors the broker's M3 stack (`app/broker/`). It is exercised only
when the `PROXY_INTRA_ORG` feature flag is true and the routing decision
(ADR-001 Phase 2) classifies the recipient as intra-org.
"""
