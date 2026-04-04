# Agent Trust Network — Presentazione del Progetto

## Il problema

Oggi gli agenti AI di organizzazioni diverse non hanno un modo standardizzato per comunicare in modo sicuro. Se un agente del buyer vuole parlare con un agente del manufacturer, chi garantisce che:

- l'agente sia chi dice di essere?
- l'organizzazione abbia autorizzato quella comunicazione?
- nessuno stia impersonando qualcuno o riproducendo messaggi vecchi?

Non esiste uno standard. Ogni integrazione è ad hoc, non auditabile, non federata.

---

## La soluzione

**Agent Trust Network** è un broker federato di fiducia inter-organizzativa per agenti AI — come ADFS, ma per LLM di aziende diverse.

Il broker garantisce:

| Garanzia | Come |
|---|---|
| Identità agente | Certificato x509 firmato dalla CA dell'organizzazione |
| Autorizzazione org | L'admin approva esplicitamente ogni agente (binding) |
| Scope controllato | Ogni sessione può usare solo le capability concesse |
| Non-ripudio | Audit log append-only su ogni evento |
| Anti-replay authn | JTI blacklist: ogni client assertion consumata una sola volta |
| Anti-replay messaggi | Nonce UUID consumato una sola volta per sessione |
| Persistenza | Sessioni sopravvivono al restart del broker, agenti riprendono automaticamente |
| Rate limiting | Sliding window per IP (auth) e per agente (sessioni, messaggi) |
| Prompt injection | Fast path regex + LLM judge (Haiku) su ogni messaggio inter-agente |
| Firma messaggi | RSA-PKCS1v15-SHA256 su ogni messaggio — verifica lato broker + non-ripudio |
| Discovery | Ricerca agenti per capability cross-org |
| Onboarding esterno | Aziende si registrano autonomamente via `join.py`, approvazione admin |
| Multi-LLM | Supporto qualsiasi backend OpenAI-compatible (Ollama, vLLM, OpenAI, Azure) |

---

## Architettura

```
Org A (buyer)                    Broker                   Org B (manufacturer)
─────────────                ─────────────────            ────────────────────
procurement-agent  ──────→   /auth/token (x509)  ←──────  sales-agent
                             /broker/sessions
                             /broker/ws (push)
                             /policy/rules
                             /registry/bindings
                             /db/audit
```

### PKI a tre livelli

```
Broker CA (RSA 4096)
├── Org CA manufacturer (RSA 2048)
│   └── sales-agent cert (RSA 2048)
└── Org CA buyer (RSA 2048)
    └── procurement-agent cert (RSA 2048)
```

Ogni agente possiede un certificato firmato dalla CA della propria organizzazione.
Il broker verifica la catena prima di emettere qualsiasi token.

---

## Demo — Supply Chain B2B

Due agenti Claude (`claude-sonnet-4-6`) negoziano un ordine d'acquisto attraverso il broker, senza mai comunicare direttamente.

### Flusso

| Step | Attore | Azione |
|---|---|---|
| 1 | TrustLink admin | `generate_certs.py` + `bootstrap.py` — PKI broker, onboarding org + agenti + policy |
| 2 | Org esterna | `join.py` — genera PKI propria, invia join request, attende approvazione |
| 3 | TrustLink admin | approva la join request via API (`x-admin-secret`) |
| 4 | manufacturer | Avvia agente, autentica via x509, si mette in ascolto su WebSocket (h24) |
| 5 | buyer | Avvia agente, autentica via x509, discovery agenti per capability, apre sessione |
| 6 | broker | Verifica policy session (buyer → manufacturer consentito) |
| 7 | manufacturer | Riceve notifica WS, accetta sessione |
| 8 | buyer → manufacturer | RFQ: richiesta offerta formale (prodotto, quantità, termini) |
| 9 | manufacturer → buyer | Offerta completa (disponibilità, prezzo scontato, lead time, pagamento) |
| 10 | buyer → manufacturer | ORDINE CONFERMATO + riepilogo + FINE |
| 11 | entrambi | Close sessione (idempotente), WebSocket chiuso — manufacturer torna in ascolto |

### Risultato demo

- Autenticazione x509 riuscita su entrambi gli agenti
- Sessione aperta, accettata e chiusa senza errori
- Negoziazione completata in 2 turni
- Audit log completo su ogni evento

---

## Firma Messaggi e Non-Ripudio

Ogni messaggio è firmato crittograficamente dal mittente prima dell'invio. Il broker verifica la firma prima di accettarlo.

**Canonical message firmato:**
```
{session_id}|{sender_agent_id}|{nonce}|{json_canonico(payload)}
```

**Cosa garantisce:**
- Il broker non può alterare il payload di un messaggio senza invalidare la firma
- Qualsiasi terza parte (auditor, regolatore) con il certificato del mittente può verificare il messaggio in modo indipendente
- L'audit log contiene `payload_hash` (SHA256) + `signature` — sufficiente per verifica forense post-hoc

---

## Prompt Injection Detection

Il broker ispeziona ogni messaggio prima di consegnarlo al destinatario.

```
Messaggio in arrivo
        │
        ▼
  Regex fast path ──── match → blocco immediato (0ms, 0 costo)
        │
        │ no match
        ▼
  Payload sospetto? ── no → consegna
   (testo lungo,
    newline, markup)
        │ sì
        ▼
  Haiku LLM judge ──── confidence ≥ 0.7 → blocco + audit log
        │
        │ clean
        ▼
  Consegna + push WS
```

Pattern rilevati dal fast path: override istruzioni, role hijack, DAN jailbreak, tag di sistema, leak del system prompt, caratteri Unicode bidirezionali.

Il LLM judge viene invocato solo su messaggi sospetti — i payload B2B strutturati (`{"type": "order", "qty": 500}`) lo saltano completamente.

---

## Target

Settori regolamentati dove tracciabilità e autenticazione inter-organizzativa sono requisiti:

- **Logistica** — ordini automatizzati tra supplier e distributor
- **Banche / KYC** — agenti che si scambiano dati verificati tra istituti
- **Sanità** — comunicazione tra sistemi clinici di ospedali diversi

---

## Stato del progetto

| Area | Stato |
|---|---|
| Broker base + JWT RS256 | ✅ |
| Registry org + binding + scope | ✅ |
| Policy engine (session + message) | ✅ |
| WebSocket push | ✅ |
| Agenti Claude reali | ✅ |
| PKI x509 + autenticazione certificati | ✅ |
| JTI blacklist (replay completo lato broker) | ✅ |
| Sessioni persistenti + resume agente | ✅ |
| Rate limiting (sliding window) | ✅ |
| Prompt injection detection (regex + LLM judge) | ✅ |
| Firma crittografica messaggi + audit trail | ✅ |
| PostgreSQL production database | ✅ |
| Discovery agenti per capability | ✅ |
| Responder h24 (sessioni multiple) | ✅ |
| Onboarding esterno (join.py + admin approval) | ✅ |
| Multi-LLM backend (OpenAI-compatible) | ✅ |
| Test suite | **94/94 passing** |

---

## Log demo

| File | Contenuto |
|---|---|
| `07-demo-certs.md` | Generazione PKI da zero |
| `07-demo-bootstrap.md` | Onboarding organizzazioni e agenti |
| `07-demo-broker.md` | Log broker uvicorn durante la demo |
| `07-demo-manufacturer.md` | Output agente manufacturer (responder) |
| `07-demo-buyer.md` | Output agente buyer (initiator) |
