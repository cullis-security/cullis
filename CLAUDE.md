# CLAUDE.md — Agent Trust Network

## Progetto

Broker di trust federato per agenti AI inter-organizzativi. Identity (x509), authorization (binding + scope), policy (default-deny), signing (RSA su ogni messaggio), audit (append-only con hash crittografico).

## Stack

- Python 3.11, FastAPI, uvicorn
- PostgreSQL 16 (asyncpg) — SQLite per test
- SQLAlchemy async
- cryptography (RSA 4096/2048, x509)
- JWT RS256 (PyJWT)
- WebSocket (FastAPI native)
- Anthropic SDK + openai SDK (multi-LLM)
- pytest-asyncio

## Comandi

```bash
# Avvia broker
./run.sh

# Test (tutti)
pytest tests/ -v

# Test singolo file
pytest tests/test_auth.py -v

# Test singolo
pytest tests/test_auth.py::test_nome -v

# Reset completo (DB + certs)
./reset.sh

# Genera PKI broker
python generate_certs.py

# Bootstrap demo (org + agenti + binding + policy)
python bootstrap.py

# Onboarding esterno
python join.py

# Avvia agente
./agent.sh --config agents/manufacturer.env
./agent.sh --config agents/buyer.env
```

## Struttura progetto

- `app/` — codice broker FastAPI
  - `app/main.py` — app FastAPI, startup, routers
  - `app/auth/` — x509 verifier, JWT, JTI blacklist
  - `app/registry/` — org, agenti, binding, capability discovery
  - `app/broker/` — sessioni, messaggi, WebSocket, persistenza
  - `app/policy/` — policy engine (session default-deny, message default-allow)
  - `app/onboarding/` — join request, admin approve/reject
  - `app/injection/` — regex fast path + LLM judge
  - `app/signing/` — RSA sign/verify, canonical format
  - `app/audit/` — append-only event log
  - `app/rate_limit/` — sliding window in-memory
  - `app/db/` — SQLAlchemy models, database setup
- `agents/` — codice agenti (client.py) + file .env
- `certs/` — certificati x509 (broker CA, org CA, agent certs)
- `tests/` — pytest-asyncio, PKI effimera in-memory
- `bootstrap.py` — setup demo automatico
- `join.py` — wizard onboarding esterno
- `generate_certs.py` — genera PKI broker

## Convenzioni codice

- Lingua: tutto il codice (variabili, funzioni, classi, commenti, log, docstring) deve essere scritto in **inglese** — senza eccezioni, anche quando si modificano file esistenti.
- Async everywhere: tutto il codice DB e HTTP è async/await
- Test: ogni nuovo modulo ha test in `tests/`. Usa la PKI effimera già presente in `conftest.py`
- Niente print per debug — usa logging
- Type hints su tutte le funzioni pubbliche
- Ogni endpoint ha il suo schema Pydantic per request/response
- Le migrazioni DB sono implicite (SQLAlchemy create_all al startup) — non usiamo Alembic per ora

## Pattern importanti

### Autenticazione
L'agente crea un JWT (`client_assertion`) firmato con la sua chiave privata e con il certificato nell'header `x5c`. Il broker:
1. Estrae il cert da x5c
2. Carica la CA dell'org dal DB
3. Verifica la catena (cert firmato dalla CA dell'org)
4. Verifica la firma JWT con la public key del cert
5. Verifica sub == CN del cert
6. Verifica binding approvato
7. Controlla JTI non usato
8. Salva il cert in DB (per verifica firme messaggi)
9. Emette access token firmato con la chiave privata del broker

### Firma messaggi
Formato canonico: `{session_id}|{sender_agent_id}|{nonce}|{canonical_json(payload)}`
Canonical JSON = sorted keys, no whitespace. Firma: RSA-PKCS1v15-SHA256.

### Policy
- Sessioni: default-deny. Serve una policy esplicita che autorizzi l'initiator a contattare la target org.
- Messaggi: default-allow. Le policy possono restringere (max size, required/blocked fields).

### Test
- Usa `conftest.py` esistente — ha la PKI effimera, il client async, i fixture per org/agenti/binding
- SQLite in-memory per i test unitari
- `test_postgres_integration.py` per test su Postgres reale (richiede container Docker attivo)
- Ogni test è indipendente — non dipende dall'ordine di esecuzione

## Sicurezza — regole non negoziabili

- Mai fidarsi del client: verificare sempre cert chain, firma, nonce, binding, policy
- Mai loggare chiavi private o secret
- Mai esporre stack trace nelle risposte HTTP (FastAPI exception handler)
- Audit log append-only: mai UPDATE o DELETE sulla tabella audit
- Rate limit su ogni endpoint esposto pubblicamente
- Prompt injection check su ogni messaggio inter-agente

## Database

- PostgreSQL per produzione/demo (asyncpg)
- SQLite per test (aiosqlite)
- Modelli in `app/db/models.py`
- `DATABASE_URL` in `.env`
- Le tabelle vengono create al startup con `create_all`

## Quando modifichi codice

1. Leggi prima il modulo esistente per capire i pattern
2. Mantieni la coerenza con lo stile esistente
3. Aggiungi test per ogni nuova funzionalità
4. Verifica che tutti i test passino: `pytest tests/ -v`
5. Se tocchi sicurezza (auth, signing, policy), ragiona sugli edge case e aggiungi test specifici
