# Agent Trust Network — Roadmap V0.2

## Visione

Agent Trust Network diventa il **trust layer unificato** per la comunicazione inter-agente (A2A) e l'accesso ai tool (MCP). Il broker non implementa i protocolli — li autorizza, firma, audita.

---

## Fase 1 — Integrazione A2A (Agent2Agent Protocol)

Obiettivo: compatibilità con lo standard A2A della Linux Foundation. Il broker diventa un trust proxy per comunicazioni A2A.

- [ ] Agent Card generation — il broker genera automaticamente l'Agent Card JSON dai binding approvati (capability, endpoint, auth)
- [ ] Endpoint discovery standard — `/.well-known/agent.json` servito dal broker per ogni agente registrato
- [ ] Formato messaggi A2A — supporto per task, message, artifact nel formato A2A (JSON-RPC)
- [ ] Mapping capability → skills A2A — le capability nei binding si mappano sulle skills dell'Agent Card
- [ ] Il broker continua a fare: verifica firma, nonce anti-replay, policy check, injection detection su ogni messaggio A2A
- [ ] Test: agent card generation, discovery, messaggio A2A attraverso il broker con firma e policy

## Fase 2 — Integrazione MCP (Model Context Protocol)

Obiettivo: il broker autorizza le tool call MCP. Le organizzazioni espongono tool, il broker fa da proxy con auth e audit.

- [ ] Registry tool MCP — le organizzazioni registrano i tool che espongono (nome, descrizione, endpoint, schema input/output)
- [ ] Binding tool → agente — il binding include quali tool MCP un agente può chiamare (scope esteso)
- [ ] Proxy MCP — l'agente chiama il broker, il broker verifica binding + capability, inoltra la chiamata al tool, logga tutto nell'audit
- [ ] Tool di esempio: `catalog.search` (ricerca prodotti nel catalogo), `order.status` (stato ordine), `inventory.check` (verifica disponibilità)
- [ ] Firma e audit su tool call — ogni chiamata tool è firmata dall'agente, verificata dal broker, loggata con payload hash
- [ ] Test: tool registration, binding tool, proxy call autorizzata, proxy call rifiutata (scope mancante), audit log su tool call

## Fase 3 — Revoca certificati

Obiettivo: invalidare agenti compromessi in tempo reale.

- [ ] `POST /admin/certs/revoke` — endpoint admin per revocare un certificato (per serial number)
- [ ] Tabella `revoked_certs` in PostgreSQL (serial_number, revoked_at, reason)
- [ ] Check revoca ad ogni autenticazione — prima di emettere il token, il broker verifica che il cert non sia revocato
- [ ] `GET /admin/certs/revoked` — lista certificati revocati
- [ ] Audit log su revoca (evento `cert.revoked`)
- [ ] Test: revoca + login bloccato, revoca cert inesistente, lista revocati

## Fase 4 — Dashboard admin web

Obiettivo: interfaccia web per gestire e monitorare il network.

- [ ] Stack: React (o HTML/JS semplice) + API broker esistenti
- [ ] Pagine:
  - Organizzazioni: lista, stato (pending/approved/rejected), approve/reject
  - Agenti: lista per org, binding, capability, stato
  - Sessioni: attive, storiche, dettaglio messaggi
  - Tool MCP: lista per org, stato, chiamate recenti
  - Audit log: ricerca per evento, agente, sessione, data
  - Certificati: lista, stato, revoca
- [ ] Autenticazione admin via `ADMIN_SECRET` (header o login form)
- [ ] Statistiche: sessioni attive, messaggi/giorno, tool call/giorno, agenti connessi

## Fase 5 — Redis + scalabilità orizzontale

Obiettivo: supporto multi-processo del broker con stato condiviso.

- [ ] Redis come store condiviso per: nonce set (anti-replay), rate limiter (contatori sliding window), sessioni attive WebSocket
- [ ] Configurazione: `REDIS_URL` in `.env`, fallback a in-memory se Redis non disponibile
- [ ] Load balancer: nginx o traefik davanti a N istanze del broker
- [ ] Test: anti-replay con due processi, rate limit condiviso, sessione WebSocket con failover
- [ ] Docker Compose aggiornato: broker (N repliche) + PostgreSQL + Redis + nginx

---

## Note architetturali

- **A2A**: il broker è un trust proxy, non reimplementa A2A. Gli agenti comunicano in formato A2A, il broker ispeziona e autorizza.
- **MCP**: il broker è un proxy, non un tool server. Le organizzazioni gestiscono i loro tool, il broker controlla l'accesso.
- **Capability**: sono generiche, definite dall'organizzazione. `order.read` era un esempio demo — il sistema supporta qualsiasi capability.
- **Proxy vs gateway**: scelta proxy per massimo controllo e audit. Overhead trascurabile (1-5ms per hop nella stessa rete).
