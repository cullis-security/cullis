Obiettivo

Integrare l'attuale Agent Trust Network con un secondo modulo dedicato alla tracciabilità di filiera, in cui gli attori della supply chain registrano eventi relativi ai lotti di prodotto.

L'idea non è usare la blockchain come "fonte di verità assoluta", ma come registro condiviso e immutabile di dichiarazioni firmate, emesse da soggetti già autenticati e autorizzati.

Problema che risolve

Nel progetto attuale il broker garantisce:

identità forte degli agenti
autorizzazione tra organizzazioni
audit dei messaggi
policy enforcement

Quello che manca è la tracciabilità persistente del bene fisico lungo la supply chain.

Per il food questo è utile per:

provenienza del lotto
chain of custody
recall rapido
audit inter-organizzativo
responsabilità in caso di problemi sanitari o logistici

Principio architetturale

La blockchain non prova che il mondo fisico sia vero.
Prova invece che:

un soggetto identificato ha fatto una certa dichiarazione
in un certo momento
con certi metadati
e che quella dichiarazione non è stata modificata dopo

Quindi il sistema deve combinare tre livelli:

Identità forte degli attori che scrivono eventi
già risolta dal broker tramite x509 / JWT / binding
Attestazioni o certificazioni esterne
esempio: certificato ente alimentare, HACCP, cold-chain compliance, audit logistico
Registro immutabile degli eventi di filiera
blockchain permissioned o ledger tamper-evident

Come si integra con il progetto attuale

Ruolo del broker esistente

Il broker continua a essere il trust layer tra organizzazioni e agenti.

Serve per:

autenticare gli agenti che registrano eventi
autorizzare quali ruoli possono scrivere quali tipi di evento
verificare che il produttore, il trasportatore, il magazzino, ecc. siano agenti approvati
firmare / auditare le richieste applicative
fare da gateway verso il ledger

Il modulo traceability è un router FastAPI montato sulla stessa app broker — non un servizio separato.
Tutti gli endpoint richiedono JWT bearer (Depends(get_current_agent) già disponibile).

Ruolo del nuovo modulo ledger

Il nuovo modulo gestisce la storia del lotto.

Serve per:

registrare gli eventi di filiera
concatenarli per lotto tramite hash chaining
ancorare hash o record su blockchain
permettere query di tracciabilità
rendere verificabile la sequenza degli eventi cross-org

Cosa si riutilizza senza toccare

| Componente | Riuso |
|---|---|
| Auth middleware | Depends(get_current_agent) su ogni endpoint |
| Firma messaggi | app/auth/message_signer.py — stesso formato canonico |
| Audit log | log_event() in app/db/audit.py — chiamata diretta |
| Policy engine | si estende con evaluate_event(), senza toccare gli altri metodi |
| Registry | ruolo agente già su DB, basta caricarlo |

Scelta tecnica

Modello ibrido off-chain + on-chain.

Off-chain (DB applicativo):
- dettagli completi del lotto
- payload completi degli eventi
- certificati e metadati
- eventuali documenti, report, log sensori

On-chain (ledger):
- hash dell'evento
- id evento
- id lotto
- tipo evento
- timestamp
- org/agent che ha emesso l'evento
- hash del certificato o riferimento al certificato
- hash dell'evento precedente del lotto

Questo evita di mettere troppi dati sulla chain e mantiene la blockchain come proof layer, non come database generale.

Attori del sistema

Attori tipici del caso food:

Producer
Logistics
Warehouse
Processor / Transformer
Retailer
Auditor / Certifier
opzionale: Regulator

Ogni attore è rappresentato nel sistema da:

organizzazione
uno o più agenti
ruolo applicativo
eventuali certificazioni associate

Concetti di dominio

1. Lot

Unità centrale della tracciabilità.

Campi:

lot_id
product_type
origin_org_id
created_at
status
quantity
unit
metadata (JSON) — paese origine, luogo produzione, data raccolta, scadenza, certificazioni bio/DOP

2. TraceabilityEvent

Ogni passaggio della filiera è un evento.

Campi:

event_id
lot_id
event_type
org_id
agent_id
timestamp
payload (JSON)
prev_event_hash  ← hash dell'evento precedente sullo stesso lotto ("genesis" per il primo)
event_hash       ← SHA256(event_id|lot_id|event_type|agent_id|timestamp_iso|canonical_json(payload)|prev_event_hash)
signature        ← firma RSA-PKCS1v15-SHA256 dell'agente mittente (riuso message_signer.py)
cert_refs (JSON)

3. Certificate / Attestation

Rappresenta un'attestazione esterna.

Campi:

cert_id
issuer
subject_org_id
cert_type
issued_at
expires_at
document_hash
status

Esempi cert_type:

food_safety_audit
haccp
cold_chain_compliance
organic_certification

4. LotCertificate

Associazione M2M tra lotti e certificazioni.

Tabella: lot_id (FK), cert_id (FK)

5. LedgerAnchor (opzionale — Fase 2)

Record scritto sull'adapter ledger per ogni evento.

Campi: event_id, lot_id, event_type, event_hash, agent_id, org_id, timestamp.
Niente payload — il broker ha già tutto, il ledger è solo proof layer.

Hash chaining

Ogni evento lega il successivo:

event_hash = SHA256(
  event_id | lot_id | event_type | agent_id | timestamp_iso | canonical_json(payload) | prev_event_hash
)

Primo evento del lotto → prev_event_hash = "genesis"
Ogni evento successivo → prev_event_hash = event_hash dell'evento precedente

La verifica della chain (endpoint /verify) ricalcola ogni hash da zero e controlla
la corrispondenza + la continuità. Se un evento è stato manomesso, la chain si spezza.

Policy per event_type

Terzo metodo evaluate_event() nel PolicyEngine esistente — senza toccare evaluate_session o evaluate_message.
Default deny: solo ruoli esplicitamente autorizzati possono emettere certi event_type.

Mappa in prima versione:

| Event type | Ruoli autorizzati |
|---|---|
| LOT_CREATED | producer |
| LOT_CERTIFIED | producer, auditor |
| SHIPMENT_DISPATCHED | producer, logistics |
| SHIPMENT_PICKED_UP | logistics |
| TEMPERATURE_RECORDED | logistics |
| SHIPMENT_RECEIVED | warehouse, processor |
| LOT_PROCESSED | processor |
| LOT_SPLIT | processor |
| LOT_MERGED | processor |
| QUALITY_CHECK_PASSED | auditor, warehouse |
| QUALITY_CHECK_FAILED | auditor, warehouse |
| RECALL_ISSUED | producer, regulator |

API

POST   /traceability/lots                       crea lotto (solo producer)
GET    /traceability/lots/{lot_id}              dettaglio lotto
POST   /traceability/lots/{lot_id}/events       registra evento (policy per event_type)
GET    /traceability/lots/{lot_id}/events       lista eventi del lotto
GET    /traceability/lots/{lot_id}/timeline     timeline ordinata
GET    /traceability/lots/{lot_id}/verify       verifica hash chain completa
POST   /traceability/certificates               registra certificazione esterna
GET    /traceability/certificates/{cert_id}     dettaglio certificazione

Esempio di flow

Producer crea LOT_CREATED
Auditor o producer collega certificati con LOT_CERTIFIED
Producer passa il lotto alla logistica con SHIPMENT_DISPATCHED
Logistics conferma presa in carico con SHIPMENT_PICKED_UP
Durante il trasporto si registrano TEMPERATURE_RECORDED
Warehouse conferma con SHIPMENT_RECEIVED
Processor registra LOT_PROCESSED
In caso di problema viene emesso RECALL_ISSUED

Regole di trust

Il ledger non accetta eventi direttamente

Ogni evento deve passare dal broker.

Ogni evento deve essere:
emesso da un agente autenticato
autorizzato in base al ruolo (evaluate_event)
firmato con la chiave privata dell'agente
collegato a un lotto esistente
collegato al precedente evento del lotto (hash chaining)

Struttura modulo

app/traceability/
  __init__.py
  db_models.py     ← Lot, TraceabilityEvent, Certificate, LotCertificate, LedgerAnchor
  models.py        ← Pydantic schemas request/response
  store.py         ← CRUD async (pattern identico a registry/store.py)
  router.py        ← endpoint FastAPI
  hash_chain.py    ← compute_event_hash(), verify_chain()
  ledger.py        ← LedgerAdapter (ABC) + LocalLedgerAdapter

Ledger adapter

Interfaccia astratta in app/traceability/ledger.py:

class LedgerAdapter(ABC):
    async def anchor(self, record: LedgerRecord) -> str: ...
    async def verify(self, event_id: str) -> LedgerRecord | None: ...

Implementazioni:

LocalLedgerAdapter    tabella ledger_anchors nel DB (append-only) — funziona subito, zero dipendenze esterne
HyperledgerAdapter    Fabric o Besu in futuro — stessa interfaccia, swap trasparente

Piano di sviluppo

Fase 1 — Backend locale (niente blockchain)

Step 1  DB models — Lot, TraceabilityEvent, Certificate, LotCertificate
Step 2  Hash chaining — compute_event_hash(), verify_chain() in hash_chain.py
Step 3  Firma eventi — riuso app/auth/message_signer.py
Step 4  evaluate_event() nel policy engine
Step 5  Store CRUD — pattern identico a registry/store.py
Step 6  Router + Pydantic schemas
Step 7  Test — PKI effimera esistente in conftest.py, fixture lot/event nuovi
Step 8  Integrazione audit log — log_event() su ogni operazione

Fase 2 — Ledger adapter

Aggiungere interfaccia LedgerAdapter astratta e LocalLedgerAdapter (tabella ledger_anchors).
Nessuna modifica al resto del codice.

Fase 3 — Blockchain permissioned

Sostituire o affiancare LocalLedgerAdapter con HyperledgerAdapter (Fabric) o BesuAdapter (Ethereum privato).
Il resto del codice non si tocca — l'interfaccia astratta isola la blockchain dal broker.

Schema impatto

Feature                         | PKI | Broker core | Auth flow | Signing  | DB
--------------------------------|-----|-------------|-----------|----------|-------------------
Traceability — Fase 1 (backend) | --  | nuovo modulo| --        | riuso    | +4 tabelle
Traceability — Fase 2 (adapter) | --  | --          | --        | --       | +ledger_anchors
Traceability — Fase 3 (chain)   | --  | --          | --        | --       | adapter swap

Cosa NON deve fare il sistema

non deve trattare la blockchain come fonte di verità del mondo fisico
non deve assumere che un evento sia "vero" solo perché è scritto on-chain
deve modellare la blockchain come proof of recorded claim
la verità fisica dipende da certificazioni esterne, audit, sensori e conferme multi-attore
