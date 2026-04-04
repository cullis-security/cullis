# Demo KYC — Banca A ↔ Banca B via Agent Trust Broker

Due agenti Claude (uno per banca) si autenticano sul broker e si scambiano
richieste di verifica identità in modo certificato e auditabile.

## Prerequisiti

```bash
# Nella root del progetto
cp .env.example .env
# Modifica JWT_SECRET_KEY in .env

pip install -r requirements.txt   # oppure usa la venv: .venv/bin/pip install ...
```

Imposta la tua chiave Anthropic nei file di config:
```bash
# in agents/banca_a.env e agents/banca_b.env
ANTHROPIC_API_KEY=sk-ant-...
```

## Avvio

### Terminale 0 — Broker

```bash
uvicorn app.main:app --reload
```

Verifica che risponda:
```bash
curl http://localhost:8000/health
# {"status":"ok","version":"0.1.0"}
```

### Terminale 1 — Agente Banca B (responder, va avviato PRIMA)

```bash
python agents/client.py --config agents/banca_b.env
```

Output atteso:
```
[banca-b::kyc-agent] Registrazione al broker (http://localhost:8000)...
[banca-b::kyc-agent] Registrazione completata.
[banca-b::kyc-agent] Login...
[banca-b::kyc-agent] Token JWT ottenuto.

[banca-b::kyc-agent] In attesa di sessioni in entrata...
```

### Terminale 2 — Agente Banca A (initiator)

```bash
python agents/client.py --config agents/banca_a.env
```

Output atteso:
```
[banca-a::kyc-agent] Registrazione al broker...
[banca-a::kyc-agent] Token JWT ottenuto.

[banca-a::kyc-agent] Apertura sessione verso banca-b::kyc-agent...
[banca-a::kyc-agent] Sessione creata: <uuid>
[banca-a::kyc-agent] In attesa che il responder accetti...
[banca-a::kyc-agent] Sessione attiva — avvio conversazione KYC.
[banca-a::kyc-agent] Invio richiesta KYC iniziale:
  → Gentile agente di Banca B, in merito al cliente CUST-001...
```

## Flusso completo

```
Banca A                           Broker                        Banca B
  │                                 │                              │
  │── POST /registry/agents ───────►│                              │
  │◄─ 201 Created ─────────────────│                              │
  │                                 │◄─ POST /registry/agents ────│
  │                                 │── 201 Created ─────────────►│
  │                                 │                              │
  │── POST /auth/token ────────────►│                              │
  │◄─ JWT ─────────────────────────│                              │
  │                                 │◄─ POST /auth/token ─────────│
  │                                 │── JWT ─────────────────────►│
  │                                 │                              │
  │── POST /broker/sessions ───────►│                              │
  │◄─ session_id (pending) ────────│                              │
  │                                 │◄─ POST /sessions/{id}/accept│
  │                                 │── 200 active ──────────────►│
  │                                 │                              │
  │── POST /sessions/{id}/messages ►│── inbox B ─────────────────►│
  │◄─ 202 ─────────────────────────│                              │
  │                                 │        [Claude Banca B]      │
  │                                 │◄─ POST /sessions/{id}/msgs ─│
  │── GET /sessions/{id}/messages ─►│                              │
  │◄─ [{seq, payload}] ────────────│                              │
  │  [Claude Banca A]               │                              │
  │── POST /sessions/{id}/messages ►│                              │
  │                      ...        │                    ...       │
  │                                 │                              │
  │                         [audit log SQLite]                     │
```

## Cosa viene auditato

Ogni evento viene scritto nell'audit log append-only (`agent_trust.db`):

```bash
sqlite3 agent_trust.db "SELECT timestamp, event_type, agent_id, result FROM audit_log;"
```

Vedrai righe tipo:
```
2026-03-26 10:00:01 | auth.token_issued        | banca-a::kyc-agent | ok
2026-03-26 10:00:02 | broker.session_created   | banca-a::kyc-agent | ok
2026-03-26 10:00:03 | broker.session_accepted  | banca-b::kyc-agent | ok
2026-03-26 10:00:04 | broker.message_forwarded | banca-a::kyc-agent | ok
2026-03-26 10:00:06 | broker.message_forwarded | banca-b::kyc-agent | ok
```

## Varianti

**Cambia cliente:** in `banca_a.env` imposta `CUSTOMER_ID=CUST-002`
(Laura Bianchi, PEP — Banca B risponderà con avviso di approfondimento).

**Più turni:** aumenta `MAX_TURNS=10` per conversazioni più elaborate.

**Reset demo:** cancella il db e riavvia il broker:
```bash
rm -f agent_trust.db test_agent_trust.db
```
