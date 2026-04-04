"""
Agent Trust Network — Revocation Tool

Lista tutti i certificati agente presenti in certs/, permette di sceglierne
uno interattivamente, lo revoca sul broker e termina il processo agente
che lo sta usando (se in esecuzione).

Usage:
  python revoke.py
  python revoke.py --broker http://localhost:8000 --certs-dir certs
"""
import argparse
import getpass
import os
import signal
import subprocess
import sys
from datetime import timezone
from pathlib import Path

import httpx
from cryptography import x509
from cryptography.x509.oid import NameOID

RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[32m"
CYAN   = "\033[36m"
YELLOW = "\033[33m"
RED    = "\033[31m"
GRAY   = "\033[90m"


def ok(msg):   print(f"  {GREEN}✓{RESET}  {msg}")
def warn(msg): print(f"  {YELLOW}!{RESET}  {msg}")
def err(msg):  print(f"  {RED}✗{RESET}  {msg}", file=sys.stderr)
def info(msg): print(f"  {CYAN}→{RESET}  {msg}")


# ── Cert discovery ─────────────────────────────────────────────────────────────

def _is_agent_cert(path: Path) -> bool:
    """Restituisce True se il file è un certificato agente (non CA, non chiave privata)."""
    name = path.name
    if name.endswith("-key.pem"):
        return False
    if name in ("ca.pem", "broker-ca.pem", "agent-key.pem"):
        return False
    if not name.endswith(".pem"):
        return False
    # Salta i cert nella root di certs/ (broker CA)
    if path.parent == path.parent.parent:
        return False
    return True


def _load_cert_info(cert_path: Path) -> dict | None:
    """
    Carica un certificato PEM e ne estrae le informazioni utili.
    Restituisce None se il file non è un cert agente valido.
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())

        # Salta CA (hanno BasicConstraints ca=True)
        try:
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
            if bc.value.ca:
                return None
        except x509.ExtensionNotFound:
            pass

        cn_attrs  = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        org_attrs = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        if not cn_attrs or not org_attrs:
            return None

        agent_id = cn_attrs[0].value
        org_id   = org_attrs[0].value

        try:
            not_after = cert.not_valid_after_utc
        except AttributeError:
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

        serial_hex = format(cert.serial_number, 'x')

        # Cerca il file .env associato (stesso stem o agent.env nella stessa cartella)
        env_path = cert_path.with_suffix(".env")
        if not env_path.exists():
            env_path = cert_path.parent / "agent.env"

        return {
            "cert_path":  cert_path,
            "env_path":   env_path if env_path.exists() else None,
            "agent_id":   agent_id,
            "org_id":     org_id,
            "serial_hex": serial_hex,
            "not_after":  not_after,
        }
    except Exception:
        return None


def discover_agent_certs(certs_dir: Path) -> list[dict]:
    """
    Scansiona ricorsivamente certs_dir e restituisce tutti i certificati agente.
    Esclude broker CA e org CA.
    """
    certs = []
    for path in sorted(certs_dir.rglob("*.pem")):
        if not _is_agent_cert(path):
            continue
        info_data = _load_cert_info(path)
        if info_data:
            certs.append(info_data)
    return certs


# ── Process management ─────────────────────────────────────────────────────────

def find_agent_processes(cert_info: dict) -> list[dict]:
    """
    Trova i processi Python che stanno usando questo certificato.
    Cerca nella command line: percorso del cert, percorso del .env, o agent_id.
    """
    try:
        result = subprocess.run(
            ["ps", "aux"],
            capture_output=True, text=True,
        )
    except Exception:
        return []

    matches = []
    cert_path_str = str(cert_info["cert_path"])
    env_path_str  = str(cert_info["env_path"]) if cert_info["env_path"] else ""
    agent_id      = cert_info["agent_id"]

    for line in result.stdout.splitlines():
        if "python" not in line.lower():
            continue
        # Cerca il percorso del cert o dell'env o dell'agent_id nella cmdline
        if (cert_path_str in line or
                (env_path_str and env_path_str in line) or
                f"--config" in line and agent_id.split("::")[0] in line):
            parts = line.split()
            try:
                pid = int(parts[1])
                cmd = " ".join(parts[10:])
                matches.append({"pid": pid, "cmd": cmd})
            except (IndexError, ValueError):
                continue

    return matches


def kill_process(pid: int) -> bool:
    """Termina il processo con SIGTERM. Restituisce True se riuscito."""
    try:
        os.kill(pid, signal.SIGTERM)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        err(f"Permesso negato per terminare PID {pid}")
        return False


# ── Broker API ─────────────────────────────────────────────────────────────────

def revoke_on_broker(
    broker_url: str,
    admin_secret: str,
    cert_info: dict,
    reason: str | None,
) -> bool:
    """Chiama POST /admin/certs/revoke sul broker. Restituisce True se riuscito."""
    try:
        resp = httpx.post(
            f"{broker_url}/admin/certs/revoke",
            json={
                "serial_hex":     cert_info["serial_hex"],
                "org_id":         cert_info["org_id"],
                "agent_id":       cert_info["agent_id"],
                "reason":         reason or "admin_revocation",
                "cert_not_after": cert_info["not_after"].isoformat(),
            },
            headers={"x-admin-secret": admin_secret},
            timeout=10,
        )
        if resp.status_code == 200:
            return True
        if resp.status_code == 409:
            warn("Certificato già revocato in precedenza.")
            return True
        err(f"Broker ha risposto {resp.status_code}: {resp.text}")
        return False
    except Exception as e:
        err(f"Errore connessione broker: {e}")
        return False


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Agent Trust Network — Revocation Tool")
    parser.add_argument("--broker",    default="http://localhost:8000")
    parser.add_argument("--certs-dir", default="certs")
    args = parser.parse_args()

    broker_url = args.broker.rstrip("/")
    certs_dir  = Path(args.certs_dir)

    print(f"\n{BOLD}╔══════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}║   Agent Trust Network — Revoke Tool      ║{RESET}")
    print(f"{BOLD}╚══════════════════════════════════════════╝{RESET}\n")

    # ── Verifica broker ───────────────────────────────────────────────────────
    try:
        httpx.get(f"{broker_url}/health", timeout=5).raise_for_status()
    except Exception as e:
        err(f"Broker non raggiungibile: {e}")
        sys.exit(1)

    # ── Scopri certificati ────────────────────────────────────────────────────
    if not certs_dir.exists():
        err(f"Directory non trovata: {certs_dir}")
        sys.exit(1)

    agent_certs = discover_agent_certs(certs_dir)

    if not agent_certs:
        warn("Nessun certificato agente trovato in certs/")
        sys.exit(0)

    # ── Lista interattiva ─────────────────────────────────────────────────────
    print(f"  {BOLD}Certificati agente disponibili:{RESET}\n")
    for i, c in enumerate(agent_certs, 1):
        expired_label = f" {RED}[SCADUTO]{RESET}" if c["not_after"].timestamp() < __import__("time").time() else ""
        print(f"  {CYAN}{i:2}.{RESET}  {BOLD}{c['agent_id']}{RESET}{expired_label}")
        print(f"        Org:     {c['org_id']}")
        print(f"        Serial:  {GRAY}{c['serial_hex'][:16]}...{RESET}")
        print(f"        Scade:   {c['not_after'].strftime('%Y-%m-%d')}")
        print(f"        Cert:    {GRAY}{c['cert_path']}{RESET}")
        print()

    try:
        scelta = input(f"  {CYAN}Scegli il numero del certificato da revocare (q=esci){RESET}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)

    if scelta.lower() in ("q", "esci", "exit"):
        sys.exit(0)

    try:
        idx = int(scelta) - 1
        if not (0 <= idx < len(agent_certs)):
            raise ValueError
    except ValueError:
        err("Scelta non valida.")
        sys.exit(1)

    selected = agent_certs[idx]

    # ── Motivo della revoca ───────────────────────────────────────────────────
    print(f"\n  {BOLD}Motivazioni comuni:{RESET}")
    print(f"    {GRAY}1) key_compromise   2) cessation_of_operation   3) altro{RESET}")
    motivo_input = input(f"  {CYAN}Motivo{RESET} {GRAY}[key_compromise]{RESET}: ").strip()
    motivo_map   = {"1": "key_compromise", "2": "cessation_of_operation"}
    reason       = motivo_map.get(motivo_input, motivo_input or "key_compromise")

    # ── Admin secret ──────────────────────────────────────────────────────────
    admin_secret = getpass.getpass(f"  {CYAN}Admin secret{RESET}: ").strip()
    if not admin_secret:
        err("Admin secret obbligatorio.")
        sys.exit(1)

    # ── Riepilogo e conferma ──────────────────────────────────────────────────
    print(f"\n  {BOLD}Riepilogo:{RESET}")
    print(f"    Agente:  {selected['agent_id']}")
    print(f"    Org:     {selected['org_id']}")
    print(f"    Motivo:  {reason}")

    procs = find_agent_processes(selected)
    if procs:
        print(f"    {YELLOW}Processi attivi da terminare:{RESET}")
        for p in procs:
            print(f"      PID {p['pid']}  {GRAY}{p['cmd'][:60]}{RESET}")
    else:
        print(f"    Processi attivi: {GRAY}nessuno trovato{RESET}")

    try:
        confirm = input(f"\n  {RED}Revocare e terminare? [y/N]{RESET}: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)

    if confirm not in ("y", "yes", "s", "si", "sì"):
        print("  Annullato.")
        sys.exit(0)

    # ── Revoca sul broker ─────────────────────────────────────────────────────
    print()
    info("Revoca in corso sul broker...")
    if revoke_on_broker(broker_url, admin_secret, selected, reason):
        ok(f"Certificato {selected['serial_hex'][:16]}... revocato.")
    else:
        err("Revoca fallita.")
        sys.exit(1)

    # ── Kill processi ─────────────────────────────────────────────────────────
    if procs:
        info("Terminazione processi agente...")
        for p in procs:
            if kill_process(p["pid"]):
                ok(f"PID {p['pid']} terminato.")
            else:
                warn(f"PID {p['pid']} non trovato (già terminato?).")

    print(f"\n{GREEN}{BOLD}Revoca completata.{RESET}")
    print(f"  {GRAY}Il certificato è ora bloccato — qualsiasi nuovo login con quel cert restituirà 401.{RESET}\n")


if __name__ == "__main__":
    main()
