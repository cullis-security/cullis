"""
SPIFFE parsing utilities for the proxy.

Mirrors the subset of app/spiffe.py needed by the egress routing decision
(ADR-001 Phase 2). Kept proxy-local to preserve the broker↔proxy module
boundary; the future cullis_core shared library (roadmap Phase 1.5) will
dedupe both copies.

Accepts two recipient formats used across the codebase:
  - SPIFFE URI:    spiffe://<trust-domain>/<org>/<agent>
  - Internal form: <org>::<agent>   (no trust domain — assumed local)
"""
import re
from urllib.parse import urlparse

_SPIFFE_SCHEME = "spiffe"
_TRUST_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$")
_PATH_COMPONENT_RE = re.compile(r"^[a-zA-Z0-9\-_\.]+$")

# ADR-007: supported ``resource_type`` path components for the 3-component
# SPIFFE form ``spiffe://<td>/<org>/<resource_type>/<resource_name>``.
# Phase 1 only ships "mcp" for DB-loaded MCP resources. Future phases may
# add "llm" (LLM routing) or "saas" (SaaS connectors) — keep the set
# explicit so ``parse_resource_spiffe`` refuses unknown types rather than
# silently widening the namespace.
_KNOWN_RESOURCE_TYPES: frozenset[str] = frozenset({"mcp"})


class InvalidRecipient(ValueError):
    """Raised when a recipient identifier cannot be parsed."""


def _is_spiffe(recipient_id: str) -> bool:
    return recipient_id.startswith("spiffe://")


def parse_spiffe(spiffe_id: str) -> tuple[str, str, str]:
    """Parse a SPIFFE URI into (trust_domain, org, agent).

    Raises InvalidRecipient on malformed input.
    """
    parsed = urlparse(spiffe_id)
    if parsed.scheme != _SPIFFE_SCHEME:
        raise InvalidRecipient(f"not a SPIFFE URI: {spiffe_id!r}")
    trust_domain = parsed.netloc
    if not trust_domain or not _TRUST_DOMAIN_RE.match(trust_domain):
        raise InvalidRecipient(f"invalid trust domain: {trust_domain!r}")
    parts = parsed.path.strip("/").split("/")
    if len(parts) != 2:
        raise InvalidRecipient(
            f"SPIFFE path must have 2 components (org/agent), got {len(parts)}"
        )
    org, agent = parts
    for name, value in (("org", org), ("agent", agent)):
        if not value or not _PATH_COMPONENT_RE.match(value):
            raise InvalidRecipient(f"invalid {name} component: {value!r}")
    if parsed.query or parsed.fragment:
        raise InvalidRecipient("SPIFFE URI must not have query or fragment")
    return trust_domain, org, agent


def parse_internal(internal_id: str) -> tuple[str, str]:
    """Parse an internal `org::agent` identifier into (org, agent).

    Raises InvalidRecipient if the separator is missing or components empty.
    """
    parts = internal_id.split("::", 1)
    if len(parts) != 2:
        raise InvalidRecipient(
            f"internal id must be 'org::agent', got {internal_id!r}"
        )
    org, agent = parts
    if not org or not agent:
        raise InvalidRecipient(f"empty component in internal id: {internal_id!r}")
    return org, agent


def parse_resource_spiffe(spiffe_id: str) -> tuple[str, str, str, str]:
    """Parse a 3-component MCP-resource SPIFFE URI (ADR-007 Phase 1).

    Expected shape: ``spiffe://<trust-domain>/<org>/<resource_type>/<resource_name>``
    where ``resource_type`` is one of the entries in ``_KNOWN_RESOURCE_TYPES``
    (today only ``"mcp"``).

    Returns ``(trust_domain, org, resource_type, resource_name)``.

    This function is intentionally **separate** from :func:`parse_spiffe`
    so the existing agent-id path stays strict at 2 components and the
    ADR-006 routing decision cannot accidentally consume a resource ID.
    """
    parsed = urlparse(spiffe_id)
    if parsed.scheme != _SPIFFE_SCHEME:
        raise InvalidRecipient(f"not a SPIFFE URI: {spiffe_id!r}")
    trust_domain = parsed.netloc
    if not trust_domain or not _TRUST_DOMAIN_RE.match(trust_domain):
        raise InvalidRecipient(f"invalid trust domain: {trust_domain!r}")
    if parsed.query or parsed.fragment:
        raise InvalidRecipient("SPIFFE URI must not have query or fragment")
    parts = parsed.path.strip("/").split("/")
    if len(parts) != 3:
        raise InvalidRecipient(
            "resource SPIFFE path must have 3 components "
            f"(org/resource_type/resource_name), got {len(parts)}"
        )
    org, resource_type, resource_name = parts
    if resource_type not in _KNOWN_RESOURCE_TYPES:
        raise InvalidRecipient(
            f"unknown resource_type {resource_type!r} "
            f"(known: {sorted(_KNOWN_RESOURCE_TYPES)})"
        )
    for name, value in (
        ("org", org),
        ("resource_name", resource_name),
    ):
        if not value or not _PATH_COMPONENT_RE.match(value):
            raise InvalidRecipient(f"invalid {name} component: {value!r}")
    return trust_domain, org, resource_type, resource_name


def is_resource_spiffe(spiffe_id: str) -> bool:
    """Return ``True`` iff ``spiffe_id`` parses as a resource SPIFFE.

    Non-raising counterpart of :func:`parse_resource_spiffe` — useful in
    routing decisions that need to branch agent-vs-resource without a
    try/except.
    """
    try:
        parse_resource_spiffe(spiffe_id)
    except (InvalidRecipient, ValueError):
        return False
    return True


def build_resource_spiffe(
    trust_domain: str,
    org: str,
    resource_name: str,
    resource_type: str = "mcp",
) -> str:
    """Assemble a canonical resource SPIFFE URI.

    Validates each component the same way :func:`parse_resource_spiffe`
    does so a round-trip (``build`` then ``parse``) is guaranteed to
    succeed or both halves raise on the same input.
    """
    if not _TRUST_DOMAIN_RE.match(trust_domain):
        raise InvalidRecipient(f"invalid trust domain: {trust_domain!r}")
    if resource_type not in _KNOWN_RESOURCE_TYPES:
        raise InvalidRecipient(
            f"unknown resource_type {resource_type!r} "
            f"(known: {sorted(_KNOWN_RESOURCE_TYPES)})"
        )
    for name, value in (
        ("org", org),
        ("resource_name", resource_name),
    ):
        if not value or not _PATH_COMPONENT_RE.match(value):
            raise InvalidRecipient(f"invalid {name} component: {value!r}")
    return f"spiffe://{trust_domain}/{org}/{resource_type}/{resource_name}"


def parse_recipient(recipient_id: str) -> tuple[str | None, str, str]:
    """Parse either form into (trust_domain | None, org, agent).

    Returns None as trust_domain for internal format — callers should treat
    that as "assumed local trust domain".
    """
    if not recipient_id:
        raise InvalidRecipient("empty recipient id")
    if _is_spiffe(recipient_id):
        return parse_spiffe(recipient_id)
    org, agent = parse_internal(recipient_id)
    return None, org, agent
