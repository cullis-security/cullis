"""
SPIFFE module — bidirectional mapping between internal agent_id and SPIFFE ID.

Standard: https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md
Format:   spiffe://trust-domain/org/agent-name

The internal format `org::agent-name` is the primary key in DB and logs.
The SPIFFE ID is the standard format for identity in JWTs (claim `sub`)
and x509 certificates (URI SAN).
"""
import re
from urllib.parse import urlparse

_SPIFFE_SCHEME = "spiffe"

# Trust domain: lowercase only, digits, hyphens, dots (no underscore per RFC)
_TRUST_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$")

# SPIFFE path components: letters, digits, hyphens, underscores, dots
_PATH_COMPONENT_RE = re.compile(r"^[a-zA-Z0-9\-_\.]+$")


def _validate_trust_domain(trust_domain: str) -> None:
    if not _TRUST_DOMAIN_RE.match(trust_domain):
        raise ValueError(f"Invalid trust domain: '{trust_domain}'")


def _validate_path_component(component: str, name: str) -> None:
    if not component:
        raise ValueError(f"SPIFFE component '{name}' is empty")
    if not _PATH_COMPONENT_RE.match(component):
        raise ValueError(f"SPIFFE component '{name}' contains invalid characters: '{component}'")


def agent_id_to_spiffe(org_id: str, agent_name: str, trust_domain: str) -> str:
    """
    Convert org_id and agent_name into a SPIFFE ID.

    Example:
        agent_id_to_spiffe("manufacturer", "sales-agent", "cullis.local")
        -> "spiffe://cullis.local/manufacturer/sales-agent"
    """
    _validate_trust_domain(trust_domain)
    _validate_path_component(org_id, "org_id")
    _validate_path_component(agent_name, "agent_name")
    return f"spiffe://{trust_domain}/{org_id}/{agent_name}"


def spiffe_to_agent_id(spiffe_id: str) -> tuple[str, str]:
    """
    Convert a SPIFFE ID into (org_id, agent_name).

    Example:
        spiffe_to_agent_id("spiffe://cullis.local/manufacturer/sales-agent")
        -> ("manufacturer", "sales-agent")

    Raises ValueError if the format is invalid.
    """
    validate_spiffe_id(spiffe_id)
    parsed = urlparse(spiffe_id)
    parts = parsed.path.strip("/").split("/")
    if len(parts) != 2:
        raise ValueError(
            f"SPIFFE ID path must have exactly 2 components (org/agent), found {len(parts)}"
        )
    org_id, agent_name = parts
    return org_id, agent_name


def internal_id_to_spiffe(agent_id: str, trust_domain: str) -> str:
    """
    Convert the internal format 'org::agent-name' into a SPIFFE ID.

    Example:
        internal_id_to_spiffe("manufacturer::sales-agent", "cullis.local")
        -> "spiffe://cullis.local/manufacturer/sales-agent"

    Raises ValueError if agent_id does not contain '::'.
    """
    parts = agent_id.split("::", 1)
    if len(parts) != 2:
        raise ValueError(
            f"Invalid agent_id format: '{agent_id}' (expected 'org::agent-name')"
        )
    org_id, agent_name = parts
    return agent_id_to_spiffe(org_id, agent_name, trust_domain)


def spiffe_to_internal_id(spiffe_id: str) -> str:
    """
    Convert a SPIFFE ID into the internal format 'org::agent-name'.

    Example:
        spiffe_to_internal_id("spiffe://cullis.local/manufacturer/sales-agent")
        -> "manufacturer::sales-agent"
    """
    org_id, agent_name = spiffe_to_agent_id(spiffe_id)
    return f"{org_id}::{agent_name}"


def parse_spiffe_san(spiffe_uri: str) -> tuple[str, str]:
    """
    Parse a SPIFFE URI and return (trust_domain, path).

    Unlike ``spiffe_to_agent_id``, this does NOT assume a 2-component
    ``org/agent-name`` path — it accepts any non-empty path, which is
    what SPIRE-issued SVIDs look like (e.g.
    ``spiffe://orga.test/workload/agent-a``). The path is returned
    without the leading slash, with internal slashes preserved.

    The last segment of the returned path is typically the usable
    workload/agent name, but that's a caller policy decision.

    Raises ValueError on malformed input.
    """
    validate_spiffe_id(spiffe_uri)
    parsed = urlparse(spiffe_uri)
    path = parsed.path.lstrip("/")
    if not path:
        raise ValueError(f"SPIFFE URI has empty path: '{spiffe_uri}'")
    # Reject empty path components (e.g. "//" in the middle) by validating
    # each one is a legal SPIFFE path component.
    for part in path.split("/"):
        _validate_path_component(part, "path segment")
    return parsed.netloc, path


def validate_spiffe_id(spiffe_id: str) -> bool:
    """
    Validate a SPIFFE ID according to the standard.
    Raises ValueError if invalid.
    Returns True if valid.
    """
    if not spiffe_id:
        raise ValueError("Empty SPIFFE ID")

    parsed = urlparse(spiffe_id)

    if parsed.scheme != _SPIFFE_SCHEME:
        raise ValueError(f"Invalid scheme: '{parsed.scheme}' (expected 'spiffe')")

    if not parsed.netloc:
        raise ValueError("Missing trust domain in SPIFFE ID")

    _validate_trust_domain(parsed.netloc)

    if not parsed.path or parsed.path == "/":
        raise ValueError("Empty SPIFFE path")

    if parsed.query or parsed.fragment:
        raise ValueError("SPIFFE ID must not contain query string or fragment")

    return True
