# ATN — Changelog implementazioni

Log delle implementazioni per sessione. Aggiornato dopo ogni sessione di lavoro.

---

## 2026-04-04 — OpenTelemetry (traces + metrics + Jaeger)

### Implementato
- **`app/telemetry.py`** (nuovo) — init TracerProvider, MeterProvider, auto-instrumentors (FastAPI, SQLAlchemy, Redis, HTTPX), graceful degradation
- **`app/telemetry_metrics.py`** (nuovo) — 7 counters (auth success/deny, session created/denied, policy allow/deny, rate limit reject) + 3 histograms (auth duration, x509 verify, PDP webhook latency)
- **`app/config.py`** — 5 settings OTel: enabled, service_name, endpoint, sampler_arg, metrics interval
- **`app/main.py`** — `init_telemetry()` nel lifespan prima di `init_db()`, `FastAPIInstrumentor.instrument_app()`, `shutdown_telemetry()` allo shutdown
- **`app/auth/router.py`** — span `auth.issue_token`, counters success/deny per reason, histogram durata
- **`app/auth/x509_verifier.py`** — span `auth.x509_verify` + child `auth.x509_chain_verify`, histogram durata
- **`app/broker/router.py`** — span `broker.create_session`, counters created/denied
- **`app/policy/engine.py`** — counters allow/deny per policy_type nella funzione _audit
- **`app/policy/webhook.py`** — span `pdp.webhook_call`, histogram latenza per org_id
- **`app/rate_limit/limiter.py`** — counter reject su entrambi i backend (in-memory + Redis)
- **`docker-compose.yml`** — servizio Jaeger all-in-one (UI 16686, OTLP 4317), env vars OTel nel broker
- **`tests/conftest.py`** — `OTEL_ENABLED=false` prima degli import app

### Dashboard — link Jaeger
- Voce "Traces" nella sidebar (admin-only), icona fulmine + icona link esterno
- Apre Jaeger UI in nuova tab, URL derivato da `OTEL_EXPORTER_OTLP_ENDPOINT`
- `_ctx()` helper passa `jaeger_url` a tutti i template via `base.html`

### Risultato
- 203 test verdi, zero regressioni
- Jaeger UI su http://localhost:16686, raggiungibile dalla dashboard
- Traces visibili per auth, sessioni, policy, PDP webhook
- Broker funziona anche senza Jaeger (graceful degradation)

---

## 2026-04-04 — Certificate Thumbprint Pinning (anti Rogue CA)

### Problema
L'Org CA poteva generare certificati arbitrari per i propri agenti con chiavi diverse. Il broker accettava qualsiasi cert firmato dalla CA e sovrascriveva `cert_pem` senza verifiche. Questo rompeva la non-repudiation e permetteva impersonation intra-org.

### Implementato
- **`cert_thumbprint` column** in `AgentRecord` — SHA-256 hex del DER del certificato
- **Pinning al primo login** — `update_agent_cert()` salva il thumbprint la prima volta, rifiuta cert con thumbprint diverso ai login successivi
- **`compute_cert_thumbprint()`** — helper per calcolare SHA-256 del DER
- **`rotate_agent_cert()`** — rotazione esplicita con invalidazione token attivi
- **x509 verifier** — ritorna anche il thumbprint, calcolato al parsing del cert DER
- **Auth router** — verifica thumbprint dopo binding check, 401 "Certificate thumbprint mismatch" se diverso
- **API endpoint** `POST /registry/agents/{id}/rotate-cert` — auth via org secret, valida cert (CA chain, CN match, scadenza), audit log con vecchio/nuovo thumbprint
- **Dashboard** — pagina "Rotate Certificate" con form upload PEM, thumbprint mostrato nella tabella agenti, link "Rotate Cert" per ogni agente
- **Validazione cert nella rotazione** — verifica firmato dalla Org CA, CN corrisponde, non scaduto
- **cert_factory.py** — `make_agent_cert_alternate()` e `make_assertion_alternate()` con cache separata per test pinning

### File modificati
- `app/registry/store.py` — colonna, helper, update_agent_cert, rotate_agent_cert
- `app/auth/x509_verifier.py` — thumbprint nel return
- `app/auth/router.py` — pinning check
- `app/registry/router.py` — endpoint rotate-cert API + _validate_cert_for_agent
- `app/registry/models.py` — RotateCertRequest, RotateCertResponse
- `app/dashboard/router.py` — GET/POST rotate-cert, thumbprint in agent list
- `app/dashboard/templates/agents.html` — colonna thumbprint + bottone Rotate
- `app/dashboard/templates/cert_rotate.html` — nuovo template
- `tests/test_auth.py` — 5 nuovi test pinning
- `tests/cert_factory.py` — alternate cert helpers

### Test
- 5 nuovi test: pin al primo login, stesso cert OK, cert diverso rifiutato, rotazione accettata, vecchio cert rifiutato dopo rotazione
- 203 test verdi, zero regressioni

---

## 2026-04-04 — Demo scenario ERP-triggered + dashboard policy + fix

### DPoP Server Nonce (RFC 9449 §8)
- Nonce server-side generato ogni 5 min con rotazione (current + previous validi)
- `app/auth/dpop.py` — `generate_dpop_nonce()`, `get_current_dpop_nonce()`, `_is_valid_nonce()`, step 12 in `verify_dpop_proof`
- `app/main.py` — middleware che aggiunge `DPoP-Nonce` header su ogni risposta API
- `agents/sdk.py` — `_dpop_nonce` field, nonce in claims, retry automatico su 401 `use_dpop_nonce`, `_authed_request` wrapper
- `tests/cert_factory.py` — `DPoPHelper` auto-primes nonce, `make_dpop_proof` accetta `nonce` param
- 5 nuovi test: nonce required, valid accepted, wrong rejected, previous still valid, response header
- 198 test verdi, zero regressioni

### Deploy produzione Docker
- Nginx reverse proxy con TLS self-signed (`nginx/nginx.conf`, `nginx/generate_tls_cert.sh`)
- WebSocket proxy pass (`/broker/ws` → upgrade connection)
- HTTP → HTTPS redirect
- `docker-compose.yml` aggiornato: aggiunto servizio nginx, `BROKER_PUBLIC_URL=https://localhost`, `FORWARDED_ALLOW_IPS=*`
- `Dockerfile` broker: aggiunto `--proxy-headers` e `--forwarded-allow-ips`
- `setup.sh` aggiornato: genera TLS cert, aspetta nginx, output con URL https

### Dashboard — Policies page
- Nuova pagina "Policies" nella sidebar (tra Sessions e Audit Log)
- Lista session policy con org, target org, capabilities, effect, status (active/inactive)
- Form "Create Session Policy": org, target org, capabilities, effect (allow/deny)
- Policy ID auto-generato come `{org}::session-{target}-v1`
- Bottone "Deactivate" (soft delete — storico preservato)
- Scoped per ruolo: admin vede tutte, org user vede solo le proprie
- CSRF protection su tutti i POST

### Precedente nella stessa sessione: Demo scenario ERP-triggered + fix dashboard

### Demo completa (`demo/`)
- `generate_org_certs.py` — due modalità: `--org` genera CA, `--agent` genera cert agente (separati)
- `create_policies.py` — crea session policy bidirezionali tra electrostore e chipfactory
- `inventory.json` — inventario simulato con soglie, config buyer hardcoded
- `inventory_watcher.py` — monitor che triggera buyer automaticamente (zero parametri)
- `buyer_agent.py` — agente on-demand con negoziazione JSON ibrida (LLM decide, messaggi strutturati), WebSocket
- `supplier_agent.py` — daemon in ascolto con WebSocket, risponde da catalogo via LLM + JSON
- `demo_commands.md` — tutti i comandi passo-passo per riprodurre la demo

### Fix dashboard
- Form "Register Agent" semplificato: solo org, agent name, display name (opzionale), capabilities
- Agent ID costruito automaticamente come `org_id::agent_name`
- Binding auto-creato e auto-approvato alla registrazione
- Bottone Delete agent con revoca binding
- Badge log silenziati (filtro uvicorn access log)

### Fix broker
- PDP webhook: se non configurato → skip (allow) invece di deny. Permette demo senza mock PDP
- Cookie `secure` condizionale: `True` solo se `BROKER_PUBLIC_URL` contiene https

---

## 2026-04-03 — Rimozione ruoli + Kit enterprise

### Rimozione sistema ruoli
Semplificazione architetturale: l'autorizzazione funziona solo tramite capabilities.
I ruoli aggiungevano complessità senza valore reale — le capabilities sono più granulari e flessibili.

**Rimosso:**
- Colonna `role` da `AgentRecord`
- Funzione `_auto_binding` (binding ora sempre esplicito)
- `list_agents_by_role()`, `list_role_policies()`
- Endpoint `/policy/roles` (POST, GET, DELETE)
- `_evaluate_role_policies()` nel policy engine
- Campo `target_role` da `SessionConditions`
- `RolePolicyCreateRequest`, `RolePolicyResponse`
- Parametro `role` da SDK, bootstrap, join_agent, policy.py
- Template HTML campo role in agent_register
- `test_role_policy.py` (13 test rimossi — non più necessari)

**File toccati:** 16 file modificati, 1 file test eliminato

### Kit integrazione enterprise
- `enterprise-kit/BYOCA.md` — guida "Bring Your Own CA" step-by-step per reparto sicurezza
- `enterprise-kit/docker-compose.agent.yml` — template Docker Compose per deploy agente lato cliente
- `enterprise-kit/pdp-template/pdp_server.py` — server PDP con regole configurabili (allowed orgs, capabilities, blocked agents)
- `enterprise-kit/pdp-template/rules.json` — esempio regole personalizzabili
- `enterprise-kit/pdp-template/Dockerfile` — container pronto per il PDP
- `enterprise-kit/quickstart.sh` — script interattivo: genera CA + cert + registra org e agente in un comando

### Risultato
- 193 test verdi, zero regressioni
- Architettura semplificata: solo capabilities, niente ruoli
- Kit enterprise pronto per onboarding clienti

---

## 2026-04-03 — Dashboard security hardening

### Audit e fix
- **CSRF protection** — token random 16 byte generato al login, salvato nel cookie firmato, verificato (timing-safe) su ogni POST. Hidden field `csrf_token` in tutti i form (onboard, approve, reject, register agent)
- **Auth enforcement approve/reject** — endpoint `POST /orgs/{id}/approve` e `/reject` erano accessibili senza autenticazione. Aggiunto `require_login` + check `is_admin`
- **Auth enforcement badge** — endpoint `/badge/pending-orgs` e `/badge/pending-sessions` leak-avano conteggi a utenti non autenticati. Aggiunto session check, pending sessions scoped per org
- **Cookie `secure=True`** — il cookie di sessione veniva trasmesso anche su HTTP. Aggiunto flag `secure` su `set_cookie` e `delete_cookie`
- **Security headers middleware** — `X-Frame-Options: DENY` (anti-clickjacking), `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy` (no camera/mic/geo), CSP con `frame-ancestors 'none'` su tutte le route `/dashboard`
- **Input validation** — org_id e agent_id validati con regex alfanumerico (max 128 char), webhook URL scheme check (solo http/https con hostname valido), capabilities format e count limit, display name max 256 char

### File modificati
- `app/dashboard/session.py` — CSRF token generation, `verify_csrf()`, `secure=True`
- `app/dashboard/router.py` — auth check su approve/reject/badge, CSRF validation su tutti i POST, input validation helpers
- `app/main.py` — security headers middleware
- `app/dashboard/templates/orgs.html` — CSRF hidden field su form approve/reject
- `app/dashboard/templates/org_onboard.html` — CSRF hidden field
- `app/dashboard/templates/agent_register.html` — CSRF hidden field
- `tests/test_dashboard.py` — da 20 a 35 test (+15 test di sicurezza: CSRF, auth enforcement, headers, input validation)

### Risultato
- 206 test verdi, zero regressioni
- Dashboard coperta contro CSRF, clickjacking, IDOR su approve/reject, info disclosure su badge, XSS (gia ok), input injection

---

## 2026-04-03 — DPoP RFC 9449 + pulizia

### Implementato
- **DPoP obbligatorio (RFC 9449)** — token binding a chiave EC P-256 efimera
  - `app/auth/dpop.py` — verify_dpop_proof, compute_jkt (RFC 7638), build_htu
  - `app/auth/dpop_jti_store.py` — store JTI in-memory con TTL (interface Redis-ready)
  - `app/auth/jwt.py` — create_access_token aggiunge `cnf.jkt`, get_current_agent verifica DPoP
  - `app/auth/router.py` — /auth/token richiede header DPoP
  - `app/auth/models.py` — `cnf` su TokenPayload, `token_type: "DPoP"`
  - `app/broker/router.py` — WebSocket auth con DPoP proof
  - `agents/sdk.py` — chiave EC efimera al login, DPoP proof per-request
  - Normalizzazione HTU per reverse proxy (`BROKER_PUBLIC_URL`, ws:// > http://)
  - `run.sh` aggiornato con --proxy-headers e --forwarded-allow-ips
  - CORS: header DPoP aggiunto a allow_headers
- **Test DPoP** — 20 unit test in test_dpop.py + 16 integration test in test_auth.py
- **Migrazione test suite** — tutti i 18 file test aggiornati per DPoP (Bearer rimosso ovunque)
- **Roadmap aggiornata** — PDP Webhook e DPoP marcati come implementati

### Decisioni architetturali
- DPoP obbligatorio (non opt-in) — ATN e un sistema nuovo, gli agenti sono macchine aggiornabili
- ES256 (P-256) per chiavi DPoP — piu veloce di RSA per chiavi efimere
- JTI tracking rigoroso con TTL 300s — Redis arrivera con il pub/sub WebSocket
- Server nonce rimandato — il JTI tracking e sufficiente per A2A
- `BROKER_PUBLIC_URL` come override canonico per HTU dietro proxy

### Pulizia
- Tutti i file in `miglioramenti/` spostati in `archive/`
- Creato `readmeV2.md` — README enterprise per presentazioni
- Creato `status.md` — cosa c'e e cosa manca
- Creato `changelog.md` — questo file

---

## 2026-04-03 — Dashboard multi-ruolo + Redis multi-worker

### Dashboard con autenticazione e ruoli
- **Login page** `/dashboard/login` con due tab: Network Admin e Organization
- **Cookie firmato** HMAC-SHA256 con scadenza 8h, httponly, samesite=lax
- **Ruolo admin**: vede tutto — tutte le org, agenti, sessioni, audit. Puo onboardare org, approve/reject, registrare agenti per qualsiasi org
- **Ruolo org**: vede solo i propri dati — propri agenti, proprie sessioni, proprio audit. Puo registrare agenti solo nella propria org. Non vede "Organizations" nella sidebar, non puo onboardare altre org
- **5 pagine** a `/dashboard`: Overview, Organizations (admin-only), Agents, Sessions, Audit Log
- **Operazioni admin**: form "Onboard Org" (CA PEM + webhook + approve diretto), bottoni Approve/Reject su org pending, form "Register Agent" con auto-binding
- **Badge HTMX** nella sidebar: contatore org pending e sessioni pending, auto-refresh ogni 10s
- **Notifiche persistenti**: tabella `notifications` in DB, create alla richiesta sessione, marcate come acted all'accept. Endpoint `GET /broker/notifications` per agenti. Sopravvivono restart.
- **20 test** in `test_dashboard.py`: login/logout, rendering, onboarding, agent registration, scoped filtering, admin-only access control
- FastAPI + Jinja2 + Tailwind CSS (CDN) + HTMX, zero dipendenze frontend, zero build step

---

## 2026-04-03 — Redis multi-worker

### Implementato
- **Redis connection pool** (`app/redis/pool.py`) — async client con graceful fallback a in-memory
- **DPoP JTI store Redis** — `SET NX EX` atomico, zero race condition tra worker
- **Rate limiter Redis** — sorted set sliding window con pipeline atomica
- **WebSocket Pub/Sub** — local-first delivery, Redis cross-worker fallback, background listener
- **Config** — `REDIS_URL` in config.py e docker-compose.yml
- **Lifespan** — init Redis al startup, graceful shutdown (listener cancel, pubsub close)
- `verify_dpop_proof` e `rate_limiter.check` convertiti in async

### Risultato
- Il broker supporta deployment multi-worker (`uvicorn --workers N`)
- Senza Redis tutto funziona come prima (fallback automatico a in-memory)
- 171 test verdi, zero regressioni

---

## Pre-2026-04-03 — Settimane 1-3

### Settimana 1 — Fondamenta
- PKI a 3 livelli (Broker CA > Org CA > Agent Certificate)
- SPIFFE ID nel SAN x509
- JWT RS256 con chiave broker
- Registry org/agenti/binding con approvazione
- Session broker con persistenza PostgreSQL
- Audit log append-only
- Rate limiting sliding window
- Test suite con PKI effimera

### Settimana 2 — Messaggistica e sicurezza
- WebSocket push real-time + fallback REST polling
- E2E AES-256-GCM + RSA-OAEP (il broker non legge il plaintext)
- Doppia firma RSA-PSS (inner non-repudiation + outer transport)
- Prompt injection detection (regex + LLM judge)
- Capability discovery cross-org
- Onboarding flow (join/approve/reject)
- Revoca certificati e token

### Settimana 3 — Enterprise
- KMS Adapter pattern (local + HashiCorp Vault KV v2)
- PDP Webhook federato (entrambe le org devono approvare, default-deny)
- Role policy con auto-binding
- SDK Python per agenti (auth, E2E, firma, WebSocket)
- Agenti demo (buyer + manufacturer) con negoziazione LLM-powered
- Test E2E completo (registrazione > auth > sessione > messaggi cifrati > replay attack > intrusion)
- Docker Compose (broker, postgres, vault, redis, mock PDP x2)
- setup.sh one-command (PKI, container, Vault init, bootstrap)
- Dockerfile broker
- generate_demo_certs.py per org demo
