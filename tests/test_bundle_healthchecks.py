"""
Regression guard for nginx sidecar healthchecks in the deploy bundles
(P3 MINOR-G).

The mastio-bundle and frontdesk-bundle ship nginx sidecars on
``nginx:1.27-alpine``. Their healthchecks probe the TLS listener over
loopback. Two failure modes have surfaced on dogfood and must stay fixed:

1. ``host.docker.internal`` in a healthcheck — that hostname is the
   PUBLIC URL the bundle advertises to siblings on the docker host. It
   is NOT routable from inside the nginx container itself, so the probe
   never reaches the listener and the container flaps ``unhealthy``
   forever even though the host can reach it fine.

2. ``localhost`` in a healthcheck — alpine ships musl libc, whose
   ``getaddrinfo`` prefers AAAA over A. Our ``listen NNNN ssl`` directives
   bind IPv4 only (``0.0.0.0:NNNN``), so wget on ``localhost`` tries
   ``::1`` first, gets Connection refused, and never falls back to IPv4.
   Use the ``127.0.0.1`` literal to skip the resolver entirely
   (PR #672 lineage, ``feedback_musl_libc_localhost_ipv6_first``).
"""
from __future__ import annotations

import pathlib
from typing import Any

import pytest
import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

# (compose path, service name) — every nginx sidecar with a healthcheck.
NGINX_SIDECARS = [
    ("packaging/mastio-bundle/docker-compose.yml", "mastio-nginx"),
    ("packaging/mastio-enterprise-bundle/docker-compose.yml", "mastio-nginx"),
    ("packaging/frontdesk-bundle/docker-compose.yml", "frontdesk-nginx"),
]


def _load_compose(rel_path: str) -> dict[str, Any]:
    path = REPO_ROOT / rel_path
    assert path.exists(), f"compose file missing: {rel_path}"
    return yaml.safe_load(path.read_text())


def _healthcheck_test_str(service: dict[str, Any]) -> str:
    """Flatten the healthcheck ``test`` list/string into a single probe string."""
    hc = service.get("healthcheck")
    assert hc, "service has no healthcheck"
    test = hc.get("test")
    assert test, "healthcheck has no test"
    if isinstance(test, list):
        return " ".join(str(t) for t in test)
    return str(test)


@pytest.mark.parametrize("compose_rel,service_name", NGINX_SIDECARS)
def test_nginx_sidecar_healthcheck_uses_loopback_literal(
    compose_rel: str, service_name: str
) -> None:
    """nginx sidecar healthchecks must probe ``127.0.0.1`` over the
    container's own TLS listener, never the public hostname and never
    the ``localhost`` symbol (musl IPv6-first trap)."""
    compose = _load_compose(compose_rel)
    services = compose.get("services") or {}
    service = services.get(service_name)
    assert service, f"{compose_rel}: service {service_name!r} missing"

    probe = _healthcheck_test_str(service)

    # 1. Public hostname must never appear — unreachable from inside the
    # container itself, causes permanent ``unhealthy`` in ``docker ps``.
    assert "host.docker.internal" not in probe, (
        f"{compose_rel}::{service_name}: healthcheck uses "
        f"'host.docker.internal' — not routable from inside the container. "
        f"Use 127.0.0.1 literal. Probe: {probe!r}"
    )

    # 2. Alpine/musl resolves ``localhost`` to ::1 first; our TLS listener
    # binds IPv4 only. Use the literal to bypass the resolver entirely.
    # We allow ``localhost`` ONLY if also paired with the v4 literal, but
    # the canonical fix is to drop ``localhost`` outright.
    assert "https://localhost" not in probe and "http://localhost" not in probe, (
        f"{compose_rel}::{service_name}: healthcheck uses 'localhost' URL — "
        f"musl libc prefers IPv6, but nginx binds IPv4 only. Use 127.0.0.1 "
        f"literal. Probe: {probe!r}"
    )

    # 3. Positive assertion: the 127.0.0.1 literal must appear in the
    # actual probe URL (not just in some comment-like fragment).
    assert "127.0.0.1" in probe, (
        f"{compose_rel}::{service_name}: healthcheck must probe via "
        f"127.0.0.1 literal. Probe: {probe!r}"
    )
