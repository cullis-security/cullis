"""
Modulo SPIFFE — mapping bidirezionale tra agent_id interno e SPIFFE ID.

Standard: https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md
Formato:  spiffe://trust-domain/org/agent-name

Il formato interno `org::agent-name` è la primary key nel DB e nei log.
Lo SPIFFE ID è il formato standard per l'identità nei JWT (claim `sub`)
e nei certificati x509 (SAN di tipo URI).
"""
import re
from urllib.parse import urlparse

_SPIFFE_SCHEME = "spiffe"

# Trust domain: solo lowercase, cifre, trattini e punti (no underscore per conformità RFC)
_TRUST_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$")

# Componenti del path SPIFFE: lettere, cifre, trattini, underscore, punti
_PATH_COMPONENT_RE = re.compile(r"^[a-zA-Z0-9\-_\.]+$")


def _validate_trust_domain(trust_domain: str) -> None:
    if not _TRUST_DOMAIN_RE.match(trust_domain):
        raise ValueError(f"Trust domain non valido: '{trust_domain}'")


def _validate_path_component(component: str, name: str) -> None:
    if not component:
        raise ValueError(f"Componente SPIFFE '{name}' vuota")
    if not _PATH_COMPONENT_RE.match(component):
        raise ValueError(f"Componente SPIFFE '{name}' contiene caratteri non validi: '{component}'")


def agent_id_to_spiffe(org_id: str, agent_name: str, trust_domain: str) -> str:
    """
    Converte org_id e agent_name in un SPIFFE ID.

    Esempio:
        agent_id_to_spiffe("manufacturer", "sales-agent", "atn.local")
        → "spiffe://atn.local/manufacturer/sales-agent"
    """
    _validate_trust_domain(trust_domain)
    _validate_path_component(org_id, "org_id")
    _validate_path_component(agent_name, "agent_name")
    return f"spiffe://{trust_domain}/{org_id}/{agent_name}"


def spiffe_to_agent_id(spiffe_id: str) -> tuple[str, str]:
    """
    Converte uno SPIFFE ID in (org_id, agent_name).

    Esempio:
        spiffe_to_agent_id("spiffe://atn.local/manufacturer/sales-agent")
        → ("manufacturer", "sales-agent")

    Raises ValueError se il formato non è valido.
    """
    validate_spiffe_id(spiffe_id)
    parsed = urlparse(spiffe_id)
    parts = parsed.path.strip("/").split("/")
    if len(parts) != 2:
        raise ValueError(
            f"SPIFFE ID path deve avere esattamente 2 componenti (org/agent), trovato {len(parts)}"
        )
    org_id, agent_name = parts
    return org_id, agent_name


def internal_id_to_spiffe(agent_id: str, trust_domain: str) -> str:
    """
    Converte il formato interno 'org::agent-name' in SPIFFE ID.

    Esempio:
        internal_id_to_spiffe("manufacturer::sales-agent", "atn.local")
        → "spiffe://atn.local/manufacturer/sales-agent"

    Raises ValueError se agent_id non contiene '::'.
    """
    parts = agent_id.split("::", 1)
    if len(parts) != 2:
        raise ValueError(
            f"Formato agent_id non valido: '{agent_id}' (atteso 'org::agent-name')"
        )
    org_id, agent_name = parts
    return agent_id_to_spiffe(org_id, agent_name, trust_domain)


def spiffe_to_internal_id(spiffe_id: str) -> str:
    """
    Converte uno SPIFFE ID nel formato interno 'org::agent-name'.

    Esempio:
        spiffe_to_internal_id("spiffe://atn.local/manufacturer/sales-agent")
        → "manufacturer::sales-agent"
    """
    org_id, agent_name = spiffe_to_agent_id(spiffe_id)
    return f"{org_id}::{agent_name}"


def validate_spiffe_id(spiffe_id: str) -> bool:
    """
    Valida un SPIFFE ID secondo lo standard.
    Raises ValueError se invalido.
    Returns True se valido.
    """
    if not spiffe_id:
        raise ValueError("SPIFFE ID vuoto")

    parsed = urlparse(spiffe_id)

    if parsed.scheme != _SPIFFE_SCHEME:
        raise ValueError(f"Schema non valido: '{parsed.scheme}' (atteso 'spiffe')")

    if not parsed.netloc:
        raise ValueError("Trust domain mancante nel SPIFFE ID")

    _validate_trust_domain(parsed.netloc)

    if not parsed.path or parsed.path == "/":
        raise ValueError("Path SPIFFE vuota")

    if parsed.query or parsed.fragment:
        raise ValueError("SPIFFE ID non deve contenere query string o fragment")

    return True
