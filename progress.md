# Agent Trust Network — Progress

## Stato: MVP completo — Postgres, discovery, onboarding esterno, responder h24

---

## Completato

### Settimana 1 — Broker base
- Broker FastAPI con JWT RS256
- Registry agenti
- Audit log append-only SQLite

### Fase 1 — Organizzazioni e binding (2026-03-27)
- Registry organizzazioni
- Binding obbligatorio org ↔ agente (pending → approved → revoked)
- Scope check su ogni operazione

### Fase 2 — Policy engine (2026-03-27)
- Session policy: default-deny (il buyer deve avere policy esplicita per aprire sessioni verso una org)
- Message policy: default-allow
- 14 test copertura supply chain

### Settimana 2 — WebSocket + agenti Claude reali (2026-03-28)
- WebSocket push notifiche (session_pending, new_message)
- Agenti Claude claude-sonnet-4-6 con ruoli initiator/responder
- Demo 03: negoziazione ordine B2B completa

### Hardening x509 (2026-03-28)
- PKI a tre livelli: broker CA (RSA 4096) → org CA (RSA 2048) → agent cert (RSA 2048)
- Autenticazione agenti via client_assertion JWT RS256 + header x5c
- Verifica catena certificati lato broker (org CA caricata in DB)
- Replay protection via jti su client_assertion
- Test con PKI effimera in-memory (conftest.py)
- `generate_certs.py` — genera PKI completa idempotente
- `reset.sh` — cancella DB e certificati per demo pulita
- `bootstrap.py` — onboarding completo: org + CA cert + agenti + binding + policy (9 oggetti, 0 skip su DB fresco)

### Fix e rifinitura demo (2026-03-28)
- Close sessione idempotente (doppio close → 200 OK invece di 409)
- Messaggio agente registrato aggiornato ("Agente presente nel registro del broker")
- Demo 06: flusso completo pulito, 42/42 test passing

---

## Stack

| Componente | Tecnologia |
|---|---|
| Broker API | Python 3.11, FastAPI, uvicorn |
| Autenticazione | JWT RS256, x509, client_assertion |
| PKI | cryptography (RSA 4096/2048, x509) |
| DB | SQLAlchemy async + PostgreSQL (asyncpg) / SQLite per test |
| Messaggistica | REST + WebSocket push |
| Agenti AI | Anthropic claude-sonnet-4-6 |
| Test | pytest-asyncio, PKI effimera in-memory |

---

### Hardening sicurezza (2026-03-28)
- JTI blacklist: protezione replay completa su client_assertion (SQLite, lazy cleanup)
- Sessioni persistenti: write-through in-memory + SQLite, restore automatico al restart
- Session resume lato agente: initiator e responder riprendono sessione esistente dopo restart
- Anti-replay nonce: UNIQUE constraint DB + nonce set in-memory ricostruito al restore
- 46/46 test passing (4 nuovi test di persistenza)

---

### Rate limiting (2026-03-28)
- Sliding window in-memory per IP su `/auth/token` (10 req/min)
- Sliding window per `agent_id` su sessioni (20/min) e messaggi (60/min)
- Fixture autouse in conftest resetta i bucket tra i test

### Prompt injection detection (2026-03-28)
- Fast path regex: 12 pattern (override, role hijack, DAN, system tag, leak, unicode bidi)
- LLM judge: `claude-haiku-4-5`, invocato solo su payload sospetti (testo lungo, newline, markup)
- Fail open se API key assente, configurabile via settings
- Blocco → HTTP 400 + audit log con source (fast_path / llm_judge)
- 75/75 test passing

---

### Firma messaggi e non-ripudio (2026-03-28)
- RSA-PKCS1v15-SHA256 su canonical `session_id|sender|nonce|json(payload)`
- Broker verifica firma al ricevimento (cert salvato in DB ad ogni login)
- Signature persistita in `session_messages` + audit log con `payload_hash`
- Verificabile post-hoc da auditor con solo il cert pubblico del mittente
- 8 test: firma valida, assente, payload alterato, session_id/nonce errati, agente sbagliato, polling, verifica auditor
- 83/83 test passing

---

---

### Migrazione Postgres (2026-03-28)
- Container Docker `agent-trust-db` su `localhost:5432` (postgres:16)
- `asyncpg` aggiunto come driver asincrono
- `DATABASE_URL` in `.env` → `postgresql+asyncpg://agent:trustme@localhost:5432/agent_trust`
- Fix `persistence.py`: rimosso `sqlite_insert` dialect-specifico, sostituito con ORM portabile
- Fix `conftest.py`: patchato `app.db.database.engine` e `app.main.AsyncSessionLocal` per evitare cross-loop asyncpg nei test
- `test_postgres_integration.py`: sessioni + messaggi firmati + replay protection su DB reale
- 83/83 test passing su SQLite + 2/2 test integrazione su Postgres reale

### Discovery agenti (2026-03-28)
- `GET /registry/agents/search?capability=order.read&capability=order.write`
- Ricerca cross-org: trova agenti di altre organizzazioni con TUTTE le capability richieste
- Esclude automaticamente la propria org
- Richiede JWT (agente autenticato)
- `client.py`: metodo `BrokerClient.discover()` + fallback automatico in `run_initiator` se `TARGET_AGENT_ID` non configurato
- 4 nuovi test: trova altri, esclude propria org, capability parziale, auth richiesta

### Responder h24 (2026-03-28)
- `run_responder` ristrutturato con loop infinito: gestisce una sessione, resetta stato, attende la prossima
- Helper `_responder_handle_session()` incapsula la logica di una singola sessione
- Detect chiusura sessione: polling su `/broker/sessions` + exit automatico
- Riconnessione WebSocket automatica tra sessioni
- Fallback polling se WS non disponibile
- Memoria LLM azzerata tra sessioni (by design — privacy inter-cliente)
- `MAX_TURNS=20` nel `.env` = max turni per singola sessione, non per l'intero processo

### Onboarding esterno (2026-03-28)
- `POST /onboarding/join` — join request pubblica: crea org in stato `pending` con CA già inclusa
- `GET /admin/orgs/pending` — lista richieste in attesa (richiede `x-admin-secret`)
- `POST /admin/orgs/{org_id}/approve` — attiva l'org
- `POST /admin/orgs/{org_id}/reject` — rifiuta la richiesta
- `ADMIN_SECRET` in `.env` (opzione A — header `x-admin-secret`)
- Login bloccato per org in stato `pending` o `rejected` (check in `x509_verifier.py`)
- `join.py` — wizard interattivo per aziende esterne: genera PKI (CA + cert agenti), invia join request, polling approvazione, crea e approva binding automaticamente dopo approvazione, salva `.env` pronti all'uso
- 7 nuovi test: pending, blocco login, lista admin, secret errato, approvazione+login, rifiuto, duplicato
- Testato end-to-end: flusso completo `join.py` → approvazione admin → `client.py` funzionante

### Fix reset.sh (2026-03-28)
- `reset.sh` ora importa tutti i modelli SQLAlchemy prima di drop_all (fix: tabelle registry non venivano eliminate)
- Flusso corretto post-reset: `./reset.sh` → `python generate_certs.py` → `./run.sh`

### Note di sicurezza
- `.env` da solo non basta per impersonare un agente: serve anche la chiave privata (`*-key.pem`)
- La superficie d'attacco reale è `certs/<org>/` — in produzione vanno in un secret manager (Vault, AWS Secrets Manager)

---

### Multi-LLM backend (2026-03-28)
- `LLM_BASE_URL` in `.env` → usa OpenAI-compatible API (Ollama, vLLM, LM Studio, OpenAI, Azure OpenAI...)
- `LLM_MODEL` → nome modello (default `claude-sonnet-4-6` su Anthropic, qualsiasi su backend esterno)
- `LLM_API_KEY` → API key per backend esterno
- Se `LLM_BASE_URL` è vuoto → Anthropic SDK (comportamento invariato)
- `openai>=1.0.0` aggiunto a `requirements.txt`
- `.env` generato da `join.py` include le variabili con commenti di esempio (Ollama, vLLM, OpenAI)

---

## Rimanente

- [ ] Demo video

---

## Roadmap V0.2

### Visione
Agent Trust Network diventa il **trust layer unificato** per la comunicazione inter-agente (A2A) e l'accesso ai tool (MCP). Il broker non implementa i protocolli — li autorizza, firma, audita.

---

### Fase 1 — Integrazione A2A (Agent2Agent Protocol)

Obiettivo: compatibilità con lo standard A2A della Linux Foundation. Il broker diventa un trust proxy per comunicazioni A2A.

- [ ] Agent Card generation — il broker genera automaticamente l'Agent Card JSON dai binding approvati (capability, endpoint, auth)
- [ ] Endpoint discovery standard — `/.well-known/agent.json` servito dal broker per ogni agente registrato
- [ ] Formato messaggi A2A — supporto per task, message, artifact nel formato A2A (JSON-RPC)
- [ ] Mapping capability → skills A2A — le capability nei binding si mappano sulle skills dell'Agent Card
- [ ] Il broker continua a fare: verifica firma, nonce anti-replay, policy check, injection detection su ogni messaggio A2A
- [ ] Test: agent card generation, discovery, messaggio A2A attraverso il broker con firma e policy

### Fase 2 — Integrazione MCP (Model Context Protocol)

Obiettivo: il broker autorizza le tool call MCP. Le organizzazioni espongono tool, il broker fa da proxy con auth e audit.

- [ ] Registry tool MCP — le organizzazioni registrano i tool che espongono (nome, descrizione, endpoint, schema input/output)
- [ ] Binding tool → agente — il binding include quali tool MCP un agente può chiamare (scope esteso)
- [ ] Proxy MCP — l'agente chiama il broker, il broker verifica binding + capability, inoltra la chiamata al tool, logga tutto nell'audit
- [ ] Tool di esempio: `catalog.search`, `order.status`, `inventory.check`
- [ ] Firma e audit su tool call — ogni chiamata tool è firmata dall'agente, verificata dal broker, loggata con payload hash
- [ ] Test: tool registration, binding tool, proxy call autorizzata, proxy call rifiutata (scope mancante), audit log su tool call

### Fase 3 — Revoca certificati

Obiettivo: invalidare agenti compromessi in tempo reale.

- [ ] `POST /admin/certs/revoke` — endpoint admin per revocare un certificato (per serial number)
- [ ] Tabella `revoked_certs` in PostgreSQL (serial_number, revoked_at, reason)
- [ ] Check revoca ad ogni autenticazione — prima di emettere il token, il broker verifica che il cert non sia revocato
- [ ] `GET /admin/certs/revoked` — lista certificati revocati
- [ ] Audit log su revoca (evento `cert.revoked`)
- [ ] Test: revoca + login bloccato, revoca cert inesistente, lista revocati

### Fase 4 — Dashboard admin web

Obiettivo: interfaccia web per gestire e monitorare il network.

- [ ] Stack: React (o HTML/JS semplice) + API broker esistenti
- [ ] Pagine: organizzazioni, agenti, sessioni, tool MCP, audit log, certificati
- [ ] Autenticazione admin via `ADMIN_SECRET`
- [ ] Statistiche: sessioni attive, messaggi/giorno, tool call/giorno, agenti connessi

### Fase 5 — Redis + scalabilità orizzontale

Obiettivo: supporto multi-processo del broker con stato condiviso.

- [ ] Redis come store condiviso per: nonce set (anti-replay), rate limiter, sessioni WebSocket
- [ ] `REDIS_URL` in `.env`, fallback a in-memory se Redis non disponibile
- [ ] Load balancer: nginx o traefik davanti a N istanze del broker
- [ ] Test: anti-replay con due processi, rate limit condiviso, sessione WebSocket con failover
- [ ] Docker Compose aggiornato: broker (N repliche) + PostgreSQL + Redis + nginx

---

### Note architetturali

- **A2A**: broker come trust proxy, non reimplementa A2A. Gli agenti comunicano in formato A2A, il broker ispeziona e autorizza.
- **MCP**: broker come proxy, non tool server. Le organizzazioni gestiscono i loro tool, il broker controlla l'accesso.
- **Capability**: generiche, definite dall'organizzazione. `order.read` era un esempio demo — supporta qualsiasi capability.
- **Proxy vs gateway**: scelta proxy per massimo controllo e audit. Overhead trascurabile (1-5ms per hop nella stessa rete).

---

## Flusso demo (partenza da zero)

```bash
./reset.sh                                    # cancella DB e certificati
python generate_certs.py                      # genera PKI da zero
./run.sh &                                    # avvia broker
sleep 2 && python bootstrap.py                # onboarding org + agenti

# Terminale 1
./agent.sh --config agents/manufacturer.env   # responder in attesa

# Terminale 2
./agent.sh --config agents/buyer.env          # initiator apre sessione
```

---

## Test

```bash
pytest tests/ -v
```

94/94 passing — copertura: auth, registry, broker, policy engine, x509, persistenza, discovery, onboarding.
