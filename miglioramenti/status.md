# ATN — Status: cosa c'e e cosa manca

Ultimo aggiornamento: 2026-04-04

---

## FATTO

### Identita e autenticazione
- [x] PKI a 3 livelli: Broker CA > Org CA > Agent Certificate
- [x] SPIFFE ID nel SAN x509 (`spiffe://trust-domain/org/agent`)
- [x] JWT RS256 firmati dal broker con chiave KMS
- [x] DPoP (RFC 9449) — token bound a chiave EC P-256 efimera, obbligatorio su ogni endpoint
- [x] JTI replay protection per client_assertion e DPoP proof
- [x] DPoP Server Nonce (RFC 9449 §8) — nonce server-side, rotazione 5 min, grace period, retry automatico nel SDK
- [x] Certificate Thumbprint Pinning — SHA-256 del cert pinnato al primo login, anti Rogue CA
- [x] Certificate Rotation — endpoint API + dashboard per rotazione esplicita con validazione CA chain
- [x] Revoca certificati (admin, preventiva)
- [x] Revoca token (self-service + admin per org)

### Crittografia messaggi
- [x] E2E AES-256-GCM + RSA-OAEP-SHA256 (il broker non legge il plaintext)
- [x] Doppia firma RSA-PSS: inner (non-repudiation) + outer (transport integrity)
- [x] Formato canonico per firma: `session_id|sender|nonce|timestamp|canonical_json`
- [x] AAD legato alla sessione (previene cross-session replay)

### Policy e autorizzazione
- [x] PDP Webhook federato — il broker chiama entrambe le org, default-deny
- [x] Binding org-agente con approvazione esplicita
- [x] Scope capability sulle sessioni (deve essere nel binding di entrambi)
- [x] Autorizzazione basata solo su capabilities (ruoli rimossi — semplificazione architetturale)
- [x] Rate limiting sliding window per endpoint/agente

### Infrastruttura
- [x] KMS Adapter pattern (local filesystem / HashiCorp Vault KV v2)
- [x] WebSocket push real-time + fallback REST polling
- [x] Audit log append-only (no UPDATE/DELETE)
- [x] Prompt injection detection (regex fast path + LLM judge)
- [x] Capability discovery cross-org
- [x] Onboarding flow (join > admin review > approve/reject)
- [x] Persistenza sessioni su PostgreSQL con restore al restart
- [x] SDK Python per agenti (auth, DPoP, E2E, firma, WebSocket)

### Deployment
- [x] Docker Compose (broker, postgres, vault, redis, mock PDP x2, nginx TLS)
- [x] Nginx reverse proxy con TLS self-signed (HTTPS, WebSocket wss://, proxy headers)
- [x] setup.sh one-command (PKI, TLS cert, container, Vault init)
- [x] Dockerfile broker (proxy-headers per forwarded proto)
- [x] generate_demo_certs.py per org demo

### Kit integrazione enterprise
- [x] Guida "Bring Your Own CA" (`enterprise-kit/BYOCA.md`) — step-by-step per reparto sicurezza
- [x] Template Docker Compose agente (`enterprise-kit/docker-compose.agent.yml`)
- [x] Template PDP webhook con regole configurabili (`enterprise-kit/pdp-template/`)
- [x] Script quickstart interattivo (`enterprise-kit/quickstart.sh`) — genera CA, cert, registra org+agente
- [x] Regole di esempio (`pdp-template/rules.json`) — allowed orgs, capabilities, blocked agents

### Redis (multi-worker ready)
- [x] Connection pool async con graceful fallback a in-memory
- [x] DPoP JTI store Redis (SET NX EX atomico, zero race condition)
- [x] Rate limiter Redis (sorted set sliding window, pipeline atomica)
- [x] WebSocket Pub/Sub (local-first, Redis cross-worker fallback)
- [x] Background listener per messaggi Redis su canali `ws:agent:{id}`

### Dashboard multi-ruolo
- [x] Login page con due tab: Network Admin / Organization
- [x] Cookie firmato HMAC-SHA256 (scadenza 8h, httponly, secure, samesite=lax)
- [x] Ruolo admin: vede tutto, onboard org, approve/reject, register agent ovunque
- [x] Ruolo org: vede solo propri agenti/sessioni/audit, registra agenti solo propri
- [x] Organizations page (admin-only, nascosta dalla sidebar per org user)
- [x] Overview con stats filtrate per ruolo
- [x] Agents con capabilities, binding status, WebSocket live
- [x] Sessions con filtro status, scoped per org
- [x] Audit Log con ricerca full-text, scoped per org
- [x] Form "Onboard Org" (admin): CA PEM, webhook URL, approve diretto
- [x] Form "Register Agent": dropdown org, agent name, capabilities, binding auto-approvato
- [x] Delete agent dalla pagina Agents (con revoca binding)
- [x] Policies page: lista session policy per org, create form (org, target org, capabilities, effect), deactivate
- [x] Bottoni Approve/Reject su org pending
- [x] Badge HTMX nella sidebar: contatore org pending e sessioni pending (auto-refresh 10s)
- [x] Notifiche persistenti in DB (session_pending, cleared on accept)
- [x] Endpoint REST `GET /broker/notifications` per agenti
- [x] 35 test, dark theme, Tailwind + HTMX, zero build frontend
- [x] Link "Traces" nella sidebar (admin-only) → apre Jaeger UI in nuova tab

### Dashboard security hardening
- [x] CSRF token per-session (random 16 byte in cookie, hidden field su ogni form POST, verify timing-safe)
- [x] Auth enforcement su approve/reject org (require_login + admin check)
- [x] Auth enforcement su badge endpoints (no data leak a utenti non autenticati)
- [x] Badge pending sessions scoped per org (org user vede solo le proprie)
- [x] Cookie `secure=True` (trasmesso solo su HTTPS)
- [x] Security headers middleware: X-Frame-Options DENY, X-Content-Type-Options nosniff, Referrer-Policy, Permissions-Policy, CSP su /dashboard
- [x] Input validation: org_id/agent_id regex alfanumerico max 128 char, webhook URL scheme check (http/https), capabilities format/count limit, display name max length
- [x] 15 test di sicurezza dedicati (CSRF, auth enforcement, security headers, input validation)

### Demo scenario ERP-triggered
- [x] `demo/generate_org_certs.py` — genera CA org o cert agente (--org / --agent), separati
- [x] `demo/create_policies.py` — crea session policy bidirezionali tra due org
- [x] `demo/inventory.json` — inventario simulato con soglie e config buyer agent
- [x] `demo/inventory_watcher.py` — monitor inventario, triggera buyer automaticamente
- [x] `demo/buyer_agent.py` — agente on-demand: auth, discover, negoziazione JSON ibrida (LLM + structured), WebSocket, salva risultato
- [x] `demo/supplier_agent.py` — agente daemon: WebSocket in ascolto, risponde con catalogo via LLM + JSON strutturato
- [x] PDP webhook skip se non configurato (allow) — permette demo senza mock PDP
- [x] Cookie `secure` condizionale (solo HTTPS) — fix login su localhost HTTP

### OpenTelemetry (traces + metrics)
- [x] TracerProvider + MeterProvider con OTLP/gRPC exporter a Jaeger
- [x] Auto-instrumentation: FastAPI, SQLAlchemy, Redis, HTTPX
- [x] Custom spans: `auth.issue_token`, `auth.x509_verify`, `auth.x509_chain_verify`, `broker.create_session`, `pdp.webhook_call`
- [x] Counters: auth success/deny, session created/denied, policy allow/deny, rate limit reject
- [x] Histograms: auth duration, x509 verify duration, PDP webhook latency
- [x] Jaeger all-in-one in docker-compose (UI su porta 16686)
- [x] Graceful degradation: broker funziona anche senza Jaeger
- [x] OTel disabilitato nei test (`OTEL_ENABLED=false`)

### Deploy Docker (testato end-to-end)
- [x] `./setup.sh` one-command: PKI, TLS cert, container build, Vault init, health check
- [x] Nginx HTTPS su porta 8443 (self-signed), WebSocket wss:// proxy
- [x] DPoP HTU corretto con `BROKER_PUBLIC_URL=https://localhost:8443`
- [x] Vault KMS async fix (`await` su `client.get`)
- [x] SDK `verify_tls=False` per self-signed localhost, WebSocket SSL context
- [x] Demo agenti (supplier + buyer) funzionanti via HTTPS + wss://

### Test
- [x] 203 test, 18 file, ~5800 righe
- [x] PKI effimera in-memory per i test (nessuna dipendenza da filesystem)
- [x] SQLite in-memory per test unitari
- [x] Mock PDP webhook nel conftest

---

## DA FARE

### Medio termine

**JWKS Key Rotation**
- Endpoint `/.well-known/jwks.json` per la chiave pubblica del broker
- Supporto rotazione chiavi con `kid` nel JWT header
- Token versioning (`ver` claim)

### Backlog (bassa priorita)

**Hardening E2E crypto**
- Limite dimensione ciphertext
- Verifica RSA key size minima (2048+)
- Fonte: `miglioramenti/archive/e2e_crypto.md`

**Validazione JWT piu rigorosa**
- Enforcement esplicito di `iss` e `aud` in `decode_token`
- Required claims check (non solo presence ma formato)
- Fonte: `miglioramenti/archive/jwt.md`

**Integrazioni future**
- OPA come policy engine alternativo ai webhook
- Beckn protocol per commerce agent-to-agent
- Hyperledger per audit ledger distribuito
- Fonte: `miglioramenti/archive/implementation.md`

---

## Architettura file

```
app/                          # Broker FastAPI (~55 moduli + templates, ~9200 righe)
  auth/                       # x509, JWT, DPoP (RFC 9449), JTI, revoca, firma messaggi
  broker/                     # Sessioni, messaggi, WebSocket, persistenza, notifiche
  dashboard/                  # Dashboard web multi-ruolo (Jinja2 + HTMX + Tailwind)
    templates/                # HTML templates (base, overview, orgs, agents, sessions, audit, login, forms)
    session.py                # Cookie firmato HMAC-SHA256 per auth dashboard
    router.py                 # Route HTML + operazioni (onboard, approve, register)
  policy/                     # Engine, store, webhook PDP
  registry/                   # Org, agenti, binding, capability discovery
  onboarding/                 # Join request, admin approve/reject
  injection/                  # Regex fast path + LLM judge
  kms/                        # KMS Adapter (local, vault)
  redis/                      # Connection pool async, graceful fallback
  rate_limit/                 # Sliding window (in-memory / Redis sorted set)
  db/                         # SQLAlchemy models, audit log
agents/                       # SDK Python + agenti demo (buyer, manufacturer)
tests/                        # 18 file test, 203 test, PKI effimera, SQLite in-memory
certs/                        # Certificati x509 generati
```
