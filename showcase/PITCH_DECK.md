# Agent Trust Network
### Federated trust infrastructure for AI agents across organizations

---

## 1. Problema

**Gli agenti AI stanno entrando nei processi aziendali reali.**
Ordini, KYC, negoziazioni, trasferimenti dati — tutto automatizzato da LLM.

Ma quando due agenti di organizzazioni diverse devono comunicare, non esiste nessuna infrastruttura di fiducia:

| Domanda | Risposta oggi |
|---|---|
| Come verifico che l'agente sia chi dice di essere? | Non puoi |
| Chi ha autorizzato questa comunicazione? | Nessuno, è ad hoc |
| Se l'agente invia un ordine da 1M€, chi ne risponde? | Impossibile provarlo |
| Come blocco un agente compromesso? | Manualmente, tardi |

**Ogni integrazione inter-organizzativa oggi è:**
- Non autenticata a livello crittografico
- Non auditabile in modo non-ripudiabile
- Non governata da policy esplicite
- Vulnerabile a impersonation, replay e prompt injection

> *È come se le banche si scambiassero bonifici senza SWIFT, senza firma e senza log.*

---

## 2. Soluzione

**Agent Trust Network** è un broker federato di fiducia per agenti AI inter-organizzativi.

Pensa ad esso come **ADFS, ma per LLM di aziende diverse.**

Ogni messaggio che passa attraverso il broker è:

- ✅ **Autenticato** — certificato x509 firmato dalla CA dell'organizzazione
- ✅ **Autorizzato** — binding esplicito approvato dall'admin, scope controllato
- ✅ **Policy-governed** — default-deny, regole esplicite per ogni coppia org→org
- ✅ **Firmato** — RSA-SHA256 su ogni messaggio, non ripudiabile
- ✅ **Auditato** — log append-only con payload hash + firma crittografica
- ✅ **Protetto** — anti-replay (JTI + nonce), rate limiting, injection detection

Gli agenti non comunicano mai direttamente. Il broker è il punto di controllo unico.

---

## 3. Architettura

```
Org A (buyer)                    Broker                   Org B (manufacturer)
─────────────                ─────────────────            ────────────────────
procurement-agent  ──────→   /auth/token (x509)  ←──────  sales-agent
                             /broker/sessions
                             /broker/ws (push)
                             /policy/rules
                             /registry/bindings
                             /audit
```

### PKI a tre livelli
```
Broker CA (RSA 4096)
├── Org CA manufacturer (RSA 2048)   ← caricata dall'admin
│   └── sales-agent cert (RSA 2048)  ← generata dall'org
└── Org CA buyer (RSA 2048)
    └── procurement-agent cert (RSA 2048)
```

### Pipeline di sicurezza su ogni autenticazione
```
Login agente
      │
      ▼
  Rate limit (IP) ───────────── 429
      │
      ▼
  Verifica chain x509 ──────── 401
      │
      ▼
  Verifica scadenza cert ────── 401
      │
      ▼
  Check revoca cert ─────────── 401  ← blocco immediato se chiave compromessa
      │
      ▼
  Verifica firma JWT ──────────401
      │
      ▼
  Binding approvato? ─────────── 403
      │
      ▼
  JTI consumato? ─────────────── 409
      │
      ▼
  Emetti access token
```

### Pipeline di sicurezza su ogni messaggio
```
Messaggio ricevuto
      │
      ▼
  Rate limit ──────────────── 429
      │
      ▼
  Nonce anti-replay ────────── 409
      │
      ▼
  Verifica firma RSA ────────── 401
      │
      ▼
  Policy check ─────────────── 403
      │
      ▼
  Injection detection ──────── 400
      │
      ▼
  Store + Audit log + WS push
```

### Stack tecnico

| Componente | Tecnologia |
|---|---|
| Broker API | Python 3.11, FastAPI, Uvicorn |
| Autenticazione | JWT RS256, x509, client_assertion |
| PKI | cryptography (RSA 4096/2048) |
| Database | SQLAlchemy async + PostgreSQL (asyncpg) |
| Messaggistica | REST + WebSocket push |
| Agenti AI | Anthropic Claude o qualsiasi backend OpenAI-compatible |
| Injection detection | Regex fast path + claude-haiku-4-5 judge |

---

## 4. Demo

**Scenario:** due aziende (buyer e manufacturer) negoziano un ordine B2B attraverso il broker, senza mai comunicare direttamente.

### Flusso live

```
1. generate_certs.py      → PKI da zero in 3 secondi
2. bootstrap.py           → onboarding org + agenti + policy
3. agent manufacturer     → autentica via x509, WebSocket in ascolto
4. agent buyer            → autentica via x509, apre sessione
5. broker                 → verifica policy (buyer→manufacturer: allowed)
6. manufacturer           → accetta sessione via WS push
7. buyer → manufacturer   → RFQ firmata (richiesta offerta)
8. manufacturer → buyer   → Offerta firmata (prezzo, disponibilità, termini)
9. buyer → manufacturer   → Ordine confermato firmato
10. entrambi              → close sessione, audit log completo
```

### Cosa si vede nell'audit log
```json
{
  "event": "broker.message_forwarded",
  "agent_id": "buyer::procurement-agent",
  "session_id": "e240018c-...",
  "payload_hash": "sha256:a3f9...",
  "signature": "base64:MEQCIBx...",
  "result": "ok"
}
```

La firma è verificabile indipendentemente dal broker da qualsiasi auditor con il certificato del mittente.

### Protezione attiva dimostrata
- **Restart broker** durante la conversazione → sessione ripristinata automaticamente, agenti riprendono
- **Replay attack** (stesso nonce) → 409 bloccato
- **Prompt injection** nel payload → 400 bloccato dal fast path regex

---

## 5. Evoluzione: tracciabilità di filiera

Il broker risolve il problema dell'identità e dell'autorizzazione tra agenti. Il passo successivo è tracciare il bene fisico che quegli agenti gestiscono.

**Il problema aggiuntivo nel food e nella supply chain:**

Un ordine B2B è autorizzato e firmato — ma da dove viene il lotto? Chi lo ha toccato? È stato mantenuto a temperatura? Se c'è un problema sanitario, si può risalire all'origine in minuti o in settimane?

**La soluzione — modulo traceability sul broker esistente:**

Ogni attore della filiera (produttore, logistica, magazzino, processore, auditor) registra eventi sul lotto attraverso il broker. Il broker garantisce già l'identità di chi scrive. La novità è il **hash chaining**: ogni evento è legato crittograficamente al precedente.

```
LOT_CREATED (produttore)
      │ hash →
LOT_CERTIFIED (auditor HACCP)
      │ hash →
SHIPMENT_DISPATCHED (produttore)
      │ hash →
TEMPERATURE_RECORDED (logistica, ogni ora)
      │ hash →
SHIPMENT_RECEIVED (magazzino)
      │ hash →
RECALL_ISSUED (regolatore)    ← risalita immediata all'origine
```

Se un evento viene manomesso, la chain si spezza — verificabile da chiunque con una query.

**Cosa riutilizza senza cambiare:** autenticazione x509, firma RSA, audit log, policy engine — il broker aggiunge solo il modulo di tracciabilità sopra l'infrastruttura esistente.

**Ledger adapter:** parte come registro append-only locale, progettato per essere sostituito con blockchain permissioned (Hyperledger Fabric, Besu) senza toccare il resto del codice.

---

## 6. Mercato

### Chi ne ha bisogno

**Settori con comunicazione inter-organizzativa regolamentata:**

| Settore | Caso d'uso | Requisito chiave |
|---|---|---|
| **Supply chain / food** | Tracciabilità lotti, ordini automatizzati, chain of custody | Non-ripudio, audit, recall |
| **Banche / fintech** | KYC inter-istituto, bonifici agentici | Compliance, firma |
| **Sanità** | Scambio dati clinici tra ospedali | Privacy, tracciabilità |
| **Legal / contratti** | Negoziazione automatizzata B2B | Non-ripudio, policy |
| **Assicurazioni** | Claims processing multi-org | Audit, authorization |

### Trend di mercato

- Il mercato degli agenti AI enterprise passerà da ~1B$ (2024) a ~28B$ (2028) — CAGR 130%
- Il 78% delle enterprise sta esplorando agenti AI per processi B2B (Gartner, 2025)
- Zero standard esistenti per autenticazione inter-organizzativa di agenti AI
- I framework esistenti (LangChain, CrewAI, AutoGen) non includono trust inter-org

### Posizionamento

```
                    Single-org          Multi-org
                 ┌──────────────┬──────────────────┐
  No Auth        │  LangChain   │    (gap di        │
                 │  CrewAI      │    mercato)       │
  ──────────────┼──────────────┼──────────────────┤
  Auth + Policy  │  (interno)   │  Agent Trust      │
                 │              │  Network ← noi    │
                 └──────────────┴──────────────────┘
```

---

## 7. Stato del progetto

### Completato (MVP hardened)

| Feature | Stato |
|---|---|
| Broker base + JWT RS256 + registry | ✅ |
| PKI x509 a tre livelli | ✅ |
| Autenticazione client_assertion | ✅ |
| Policy engine (session default-deny) + role policy | ✅ |
| WebSocket push real-time | ✅ |
| Agenti Claude reali (B2B demo funzionante) | ✅ |
| JTI blacklist (anti-replay auth) | ✅ |
| Sessioni persistenti + resume agente | ✅ |
| Rate limiting sliding window | ✅ |
| Prompt injection detection (regex + Haiku) | ✅ |
| Firma messaggi RSA + audit trail non-ripudiabile | ✅ |
| PostgreSQL production database | ✅ |
| Discovery agenti per capability | ✅ |
| Responder h24 (sessioni multiple senza restart) | ✅ |
| Onboarding esterno (join.py wizard + admin approval) | ✅ |
| Multi-LLM backend (OpenAI-compatible) | ✅ |
| Revoca certificati in tempo reale (revoke.py) | ✅ |
| **Test suite** | **94/94 passing** |

### Roadmap

| Fase | Contenuto | Quando |
|---|---|---|
| **V0.2** | Tracciabilità di filiera (lotti, eventi, hash chaining, ledger adapter) | Q2 2026 |
| **V0.3** | A2A protocol integration, MCP proxy, dashboard admin | Q3 2026 |
| **V0.4** | SDK Python/TypeScript per agenti, marketplace capability | Q3 2026 |
| **V1.0** | Deployment cloud-managed, SLA, compliance SOC2 | Q4 2026 |

---

## 8. Ask

**Cosa stiamo cercando:**

### Opzione A — Partner tecnico early adopter
Organizzazione con un caso d'uso reale di comunicazione inter-agente (supply chain, food, fintech, sanità) disposta a co-sviluppare una pilot integration.

**Offriamo:** deployment dedicato, supporto integrazione, co-authorship su case study.

Il caso supply chain / food è particolarmente interessante perché il broker esistente si integra con il modulo traceability V0.2 — onboarding rapido senza infrastruttura blockchain da costruire da zero.

### Opzione B — Pre-seed
**€150K–300K** per:
- Team: 2 ingegneri full-time per 12 mesi
- Infrastruttura cloud + certificazioni compliance
- Go-to-market: 3 pilot con enterprise nei settori target

**Milestones finanziati:**
1. V0.2 — tracciabilità di filiera production-ready — mese 3
2. Primo pilot enterprise live (supply chain o fintech) — mese 6
3. SDK pubblico + 10 organizzazioni onboard — mese 12

---

*Agent Trust Network — perché gli agenti AI hanno bisogno di passaporti, non solo di chiavi API.*

**Contatti:** [da compilare]
**Repository:** [da compilare]
**Demo live:** `./reset.sh && python generate_certs.py && ./run.sh & sleep 2 && python bootstrap.py`
