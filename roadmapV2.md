Agent Trust Network — Stato & Evoluzione                                                                                           
                                                                                                                                     
  Cosa abbiamo implementato (MVP completo)                                                                                           
                                                                                                                                     
  Il broker è funzionante end-to-end:                                                                                                
                                                                                                                                     
  ┌─────────────────────┬────────────────────────────────────────────────────────────────────────────────────────┐                   
  │        Layer        │                                         Stato                                          │
  ├─────────────────────┼────────────────────────────────────────────────────────────────────────────────────────┤                   
  │ Identity            │ x509 3-livelli (Broker CA → Org CA → Agent cert) + SPIFFE URI in SAN                   │
  ├─────────────────────┼────────────────────────────────────────────────────────────────────────────────────────┤                   
  │ Autenticazione      │ JWT RS256 via client assertion, verifica chain x509, SAN SPIFFE opzionale/obbligatorio │                   
  ├─────────────────────┼────────────────────────────────────────────────────────────────────────────────────────┤                   
  │ Autorizzazione      │ Binding esplicito + scope, policy engine default-deny sessioni                         │                   
  ├─────────────────────┼────────────────────────────────────────────────────────────────────────────────────────┤                   
  │ Non-repudiation     │ Firma RSA-PKCS1v15-SHA256 su ogni messaggio, canonical format                          │
  ├─────────────────────┼────────────────────────────────────────────────────────────────────────────────────────┤                   
  │ Replay protection   │ JTI blacklist (auth), nonce UUID (messaggi)                                            │
  ├─────────────────────┼────────────────────────────────────────────────────────────────────────────────────────┤                   
  │ Audit               │ Append-only log con SHA256 hash del payload                                            │
  ├─────────────────────┼────────────────────────────────────────────────────────────────────────────────────────┤                   
  │ Injection detection │ Regex fast path + Haiku LLM judge                                                      │
  ├─────────────────────┼────────────────────────────────────────────────────────────────────────────────────────┤                   
  │ Persistence         │ Session restore su restart                                                             │
  ├─────────────────────┼────────────────────────────────────────────────────────────────────────────────────────┤                   
  │ Transport           │ REST + WebSocket push                                                                  │
  ├─────────────────────┼────────────────────────────────────────────────────────────────────────────────────────┤
  │ Test                │ 94+ test, PKI effimera in-memory, SQLite                                               │
  └─────────────────────┴────────────────────────────────────────────────────────────────────────────────────────┘                   
  
  SPIFFE è integrato nei punti chiave: generazione cert (generate_certs.py, cert_factory.py), verifica SAN in autenticazione         
  (x509_verifier.py), claim sub nel JWT emesso dal broker, esposizione agent_uri nel registry.
                                                                                                                                     
  ---             
  Cosa stanno standardizzando gli esperti IETF
                                                                                                                                     
  I due draft nella cartella drafts/ rappresentano lo stato dell'arte del settore:
                                                                                                                                     
  WIMSE — Workload Identity in a Multi-System Environment
                                                                                                                                     
  Draft IETF che definisce l'identità dei workload nei sistemi distribuiti. Tre building block:                                      
  1. Trust domain — confine di fiducia (noi: atn.local, in prod FQDN)
  2. Workload identifier — SPIFFE ID come spiffe://trust.domain/path                                                                 
  3. Workload identity credential — X.509 oppure WIMSE Proof Token (WPT, JWT firmato per singola chiamata HTTP)
                                                                                                                                     
  Il concetto chiave che WIMSE introduce e noi non abbiamo ancora è la context propagation: quando il workload A chiama B che chiama 
  C, la catena di deleghe deve essere portata avanti in modo verificabile. WIMSE definisce un meccanismo per propagare il "caller    
  chain" attraverso i servizi.                                                                                                       
                                                                                                                                     
  Draft KLRC — AI Agent Authentication and Authorization                                                                             
   
  Estende WIMSE specificamente per agenti AI. Le aggiunte principali rispetto a WIMSE puro:                                          
                  
  - Remote attestation evidence — prova crittografica di quale modello/versione è in esecuzione, su quale hardware, con quale        
  configurazione. Va ben oltre il certificato.
  - Transaction tokens — token a vita breve legati a una singola operazione, non solo alla sessione. Portano con sé il context della 
  richiesta originale (chi ha iniziato, con quale scopo).                                                                            
  - User delegation chain — separazione esplicita tra "chi è l'agente" (workload identity) e "per conto di chi agisce" (user
  identity). Noi oggi passiamo solo l'identity del workload.                                                                         
  - Capability delegation — un agente può delegare sottoinsieme delle sue capability a un sub-agente in modo verificabile e
  revocabile, OAuth 2.0 style.                                                                                                       
  - HTTP Message Signatures (RFC 9421) — firma sugli header HTTP (non solo sul payload), coprendo metodo, URL, timestamp. Noi
  firmiamo il payload in formato canonico, loro firmano l'intera richiesta HTTP.                                                     
                  
  ---                                                                                                                                
  Gap tra noi e gli standard
                            
  ┌────────────────────────┬─────────────────┬────────────────────────────────────────────────────────────────────────────────┐
  │        Feature         │       Noi       │                                   WIMSE/KLRC                                   │      
  ├────────────────────────┼─────────────────┼────────────────────────────────────────────────────────────────────────────────┤
  │ SPIFFE ID              │ ✅ implementato │ ✅ conforme                                                                    │      
  ├────────────────────────┼─────────────────┼────────────────────────────────────────────────────────────────────────────────┤
  │ x509 chain             │ ✅ 3 livelli    │ ✅ conforme                                                                    │      
  ├────────────────────────┼─────────────────┼────────────────────────────────────────────────────────────────────────────────┤
  │ JWT RS256              │ ✅ sessione     │ ✅ conforme                                                                    │      
  ├────────────────────────┼─────────────────┼────────────────────────────────────────────────────────────────────────────────┤      
  │ Message signing        │ ✅ payload RSA  │ Parziale — loro usano HTTP Message Signatures (RFC 9421) sull'intera richiesta │
  ├────────────────────────┼─────────────────┼────────────────────────────────────────────────────────────────────────────────┤      
  │ Context propagation    │ ❌ non c'è      │ WIMSE WPT per caller chain                                                     │
  ├────────────────────────┼─────────────────┼────────────────────────────────────────────────────────────────────────────────┤      
  │ User delegation        │ ❌ non c'è      │ KLRC: separare workload identity da user identity                              │
  ├────────────────────────┼─────────────────┼────────────────────────────────────────────────────────────────────────────────┤      
  │ Transaction tokens     │ ❌ non c'è      │ KLRC: token per singola operazione                                             │
  ├────────────────────────┼─────────────────┼────────────────────────────────────────────────────────────────────────────────┤      
  │ Remote attestation     │ ❌ non c'è      │ KLRC: prova di quale modello/versione è in esecuzione                          │
  ├────────────────────────┼─────────────────┼────────────────────────────────────────────────────────────────────────────────┤      
  │ Capability delegation  │ Binding statico │ KLRC: delegation chain verificabile e revocabile                               │
  ├────────────────────────┼─────────────────┼────────────────────────────────────────────────────────────────────────────────┤      
  │ Certificate revocation │ ✅ implementato │ Tabella revoked_certs, check in x509_verifier step 7, revoke.py interattivo   │
  └────────────────────────┴─────────────────┴────────────────────────────────────────────────────────────────────────────────┘      
                  
  ---                                                                                                                                
  Come potrebbe evolvere il progetto
                                    
  In ordine di impatto e fattibilità:
                                                                                                                                     
  1. WIMSE Proof Tokens (breve termine)                                                                                              
  Affiancare al JWT di sessione un WPT per ogni chiamata HTTP verso servizi esterni. Il WPT è un JWT firmato con la chiave del       
  workload, con audience = URL target e scadenza brevissima (60s). Risolve il problema del "chi ha effettivamente fatto questa       
  chiamata adesso". Implementazione: nuovo endpoint del broker che emette WPT on-demand, integrato nel client.py.
                                                                                                                                     
  2. User delegation chain (medio termine)
  Aggiungere al JWT un claim act (actor) o may_act (RFC 8693) per portare l'identità dell'utente che ha delegato all'agente. Noi oggi
   perdiamo questa informazione appena l'agente si autentica. Questo è cruciale per audit e compliance: sapere che "buyer-agent ha   
  agito su delega di mario.rossi@buyerorg.com".
                                                                                                                                     
  3. HTTP Message Signatures — RFC 9421 (medio termine)
  Sostituire o affiancare la nostra firma sul payload canonico con firme sugli header HTTP (metodo, path, digest, timestamp).
  Compatibilità con eventuali gateway o proxy intermediari che verificano le firme.                                                  
   
  4. Certificate revocation ✅ FATTO
  Tabella revoked_certs (serial_hex PK, lazy cleanup). Check in x509_verifier step 7 (dopo verifica chain e temporale,
  prima dell'uso della chiave pubblica). Endpoint POST /admin/certs/revoke + GET /admin/certs/revoked.
  revoke.py: lista interattiva dei cert in certs/, revoca sul broker, SIGTERM al processo agente.
                                                                                                                                     
  5. Remote attestation (lungo termine)
  Il più ambizioso. Permettere a un agente di dimostrare crittograficamente quale modello sta usando (hash del modello, del prompt di
   sistema, dei parametri). Rilevante se vogliamo garantire che manufacturer::sales-agent sta girando con Claude Sonnet e non con un 
  modello locale non verificato. Richiede integrazione con TEE (Trusted Execution Environment) o attestation service dell'LLM
  provider.                                                                                                                          
                  
  ---                                                                                                                                
  Posizionamento rispetto agli standard
                                                                                                                                     
  Siamo già conformi alla parte identity e authentication di WIMSE/KLRC. Siamo in anticipo su molti framework del settore perché
  abbiamo già:                                                                                                                       
  - la PKI 3-livelli
  - SPIFFE nei certificati                                                                                                           
  - firma sui messaggi    
  - audit append-only 
  - policy engine                                                                                                                    
                 
  I gap principali sono nella parte authorization e delegation (cosa stai facendo, per conto di chi, con quale catena di delega), che
   è la parte più difficile e più attuale nella ricerca.

  ---
  Traceability di filiera

  Nuovo asse di evoluzione: modulo app/traceability/ montato sulla stessa app broker.

  Problema che risolve: il broker garantisce identità, autorizzazione e audit dei messaggi tra agenti, ma non traccia la storia
  del bene fisico lungo la supply chain. Il modulo traceability aggiunge questa dimensione — provenienza del lotto, chain of
  custody, recall rapido, audit inter-organizzativo.

  Principio: la blockchain non prova che il mondo fisico sia vero. Prova che un soggetto identificato ha fatto una certa
  dichiarazione, in un certo momento, e che quella dichiarazione non è stata modificata dopo. La verità fisica dipende da
  certificazioni esterne, audit e conferme multi-attore.

  Cosa si riutilizza senza toccare:
  - Auth middleware — Depends(get_current_agent) su ogni endpoint
  - Firma messaggi — app/auth/message_signer.py, stesso formato canonico
  - Audit log — log_event() in app/db/audit.py
  - Policy engine — si estende con evaluate_event(), senza toccare gli altri metodi
  - Registry — ruolo agente già su DB

  Concetti di dominio:
  - Lot — unità centrale della tracciabilità (lot_id, product_type, origin_org_id, status, quantity, metadata)
  - TraceabilityEvent — ogni passaggio della filiera, con hash chaining:
    event_hash = SHA256(event_id|lot_id|event_type|agent_id|timestamp_iso|canonical_json(payload)|prev_event_hash)
  - Certificate/Attestation — certificazioni esterne (HACCP, cold-chain, organic, food safety audit)
  - LotCertificate — associazione M2M tra lotti e certificazioni

  Event type supportati: LOT_CREATED, LOT_CERTIFIED, SHIPMENT_DISPATCHED, SHIPMENT_PICKED_UP, TEMPERATURE_RECORDED,
  SHIPMENT_RECEIVED, LOT_PROCESSED, LOT_SPLIT, LOT_MERGED, QUALITY_CHECK_PASSED, QUALITY_CHECK_FAILED, RECALL_ISSUED

  Policy per event_type (evaluate_event, default deny):
  - solo producer → LOT_CREATED
  - solo logistics → SHIPMENT_PICKED_UP, TEMPERATURE_RECORDED
  - solo auditor/producer → LOT_CERTIFIED
  - solo producer/regulator → RECALL_ISSUED

  Ledger adapter astratto (LedgerAdapter ABC):
  - Fase 1: LocalLedgerAdapter — tabella ledger_anchors append-only, zero dipendenze esterne
  - Fase 3: HyperledgerAdapter / BesuAdapter — swap trasparente, resto del codice invariato

  API:
  POST   /traceability/lots
  GET    /traceability/lots/{lot_id}
  POST   /traceability/lots/{lot_id}/events
  GET    /traceability/lots/{lot_id}/timeline
  GET    /traceability/lots/{lot_id}/verify     ← verifica hash chain completa
  POST   /traceability/certificates
  GET    /traceability/certificates/{cert_id}

  Struttura modulo: app/traceability/ con db_models.py, models.py, store.py, router.py, hash_chain.py, ledger.py

---                                                                                                                                
  La PKI attuale è già allineata
                                                                                                                                     
  La struttura a 3 livelli (Broker CA → Org CA → Agent cert) è esattamente quello che WIMSE raccomanda. Non c'è nulla da cambiare lì.
   Il trust domain SPIFFE nei SAN è già conforme. Questa parte è solida.                                                             
                  
  ---                                                                                                                                
  Analisi impatto per feature
                             
  WIMSE Proof Tokens — impatto basso, additivo
  Il WPT è un JWT firmato con la chiave privata dell'agente (già in certs/), con audience = URL target e scadenza 60s. Il broker     
  emette l'access token come oggi; il WPT è un secondo tipo di token che il client genera da solo per chiamate verso servizi terzi.  
  Nuovo metodo in client.py, nessun cambio al broker o alla PKI.                                                                     
                                                                                                                                     
  User delegation chain — impatto basso, additivo
  RFC 8693 aggiunge claim act al JWT. Il broker accetta un campo opzionale delegated_by nella request di autenticazione (email utente
   o identità opaca), lo porta nel JWT emesso. Modifica a app/auth/router.py, app/auth/jwt.py, schema Pydantic. La PKI non si tocca. 
   
  Certificate revocation — impatto basso, additivo                                                                                   
  Tabella revoked_certs in DB, check in x509_verifier.py dopo la verifica chain. Endpoint POST /admin/certs/revoke. È già in roadmap
  V0.2 e non tocca l'architettura.                                                                                                   
   
  HTTP Message Signatures (RFC 9421) — impatto medio, ma localizzato                                                                 
  Questo è l'unico che cambia un modulo esistente: app/auth/message_signer.py. RFC 9421 firma header HTTP (metodo, path, digest,
  timestamp) invece del solo payload canonico. Le opzioni sono due: affiancare i due formati (backward compatible) oppure sostituire.
   In ogni caso è tutto dentro il modulo signing, il resto del broker non cambia.
                                                                                                                                     
  Remote attestation — impatto alto, non urgente                                                                                     
  Questo è l'unico che potrebbe richiedere estensioni al modello identity. Attestare "quale modello/versione sta girando" richiede o
  nuove estensioni x509 nel cert o un servizio di attestation esterno. Non è implementabile senza infrastruttura esterna (TEE,       
  attestation service del provider LLM). Va valutato a parte quando il use case lo richiede concretamente.
                                                                                                                                     
  ---             
  Schema riassuntivo

  Feature                   | PKI  | Broker core  | Auth flow | Signing  | DB
  --------------------------|------|--------------|-----------|----------|-------------------
  WIMSE Proof Tokens        |  --  |     --       |    --     |  nuovo   | --
  User delegation chain     |  --  |     --       | +campo    |   --     | --
  Certificate revocation    |  --  |  ✅done      | ✅done    |   --     | ✅done
  HTTP Message Signatures   |  --  |     --       |    --     | modifica | --
  Remote attestation        |  ?   |   rifare     |  rifare   |   --     | +tabella
  Traceability — Fase 1     |  --  | nuovo modulo |    --     |  riuso   | +4 tabelle
  Traceability — Fase 2     |  --  |     --       |    --     |   --     | +ledger_anchors
  Traceability — Fase 3     |  --  |     --       |    --     |   --     | adapter swap

  ---
  Conclusione

  I primi quattro (WIMSE, delegation, revocation, HTTP signatures) si aggiungono sopra quello che c'è, senza toccare la struttura
  del broker o della PKI. Il quinto (remote attestation) è l'unico architetturalmente disruttivo, ma è anche il più lontano dalla
  realtà operativa oggi — i provider LLM non espongono ancora attestation services usabili.

  La traceability di filiera è il sesto asse di evoluzione: un modulo nuovo montato sulla stessa app broker, che riutilizza
  autenticazione, firma, audit e policy engine esistenti. Il ledger parte come append-only locale e può essere sostituito con
  blockchain permissioned (Hyperledger Fabric / Besu) tramite un adapter astratto, senza toccare il resto del codice.

  Il sistema attuale è costruito abbastanza bene da reggere queste evoluzioni senza dover rifare nulla di fondamentale.



Cosa è stato fatto

  Broker (7 file modificati):
  - app/registry/store.py — colonna role su AgentRecord, list_agents_by_role()
  - app/registry/models.py — campo role in AgentRegisterRequest e AgentResponse
  - app/registry/router.py — funzione _auto_binding(): se esiste una role policy per il ruolo, il binding viene creato e approvato
  automaticamente; altrimenti pending come prima
  - app/policy/models.py — aggiunto target_role a SessionConditions
  - app/policy/store.py — list_role_policies(db, role, policy_type)
  - app/policy/engine.py — evaluate_session ora controlla prima le role policy (initiator_role → target_role), poi fallback alle org
  policy
  - app/policy/router.py — nuovi endpoint POST/GET/DELETE /policy/roles protetti da X-Admin-Secret
  - app/broker/router.py — carica il ruolo di initiator e target, li passa all'engine
  - shell.nix — aggiunge gcc.cc.lib e LD_LIBRARY_PATH per greenlet/SQLAlchemy

  Script CLI (2 file):
  - policy.py — riscritto: menu interattivo per creare/visualizzare role policy (admin)
  - join_agent.py — nuovo: genera cert firmato dalla CA locale, registra agente con ruolo, salva env config

  Test (1 file nuovo):
  - tests/test_role_policy.py — 13 test: registrazione con role, auto-binding, engine con role policy, backward compat, endpoint
  admin

  Flusso operativo ora

  # Admin — una volta sola
  python policy.py          # crea role:buyer → role:supplier

  # Org A si unisce
  python join.py            # registra org, aspetta approvazione

  # Agente buyer
  python join_agent.py --org acme --name buyer-1 --role buyer \
                      --capabilities order.read,order.write
  # → binding auto-approvato (role policy trovata)
  # → salva certs/acme/buyer-1/agent.env

  # Avvia
  ./agent.sh --config certs/acme/buyer-1/agent.env


Il client.py usa AGENT_ROLE solo per initiator/responder. Non serve aggiungere nulla negli env file — il ROLE per il registry è già
   gestito da bootstrap.py al momento della registrazione.                                                                        
                                                                                                                                     
  Verifico che il bootstrap.py risultante sia corretto:                                                                              
                                                                                                                                     
  Read 1 file (ctrl+o to expand)                                                                                                     
                                                                                                                                  
● La funzione create_session_policy è rimasta nel file ma non è più chiamata dal main. La lascio per retrocompat (può servire per    
  creare policy org-specifiche legacy), ma la rinomino con un commento chiaro. Verifico che non ci siano warn ridefiniti nel loop:
                                                                                                                                     
● Update(bootstrap.py)                                                                                                               
  ⎿  Added 1 line, removed 2 lines                                                                                                   
      335              if b and b["status"] == "approved":                                                                           
      336                  ok(f"{agent_id}  →  binding {b['status']}  scope={b['scope']}")                                        
      337              elif b:                                                                                                       
      338 -                warn = lambda m: print(f"  {YELLOW}!{RESET} {m}")                                                      
      339 -                warn(f"{agent_id}  →  binding {b['status']} (role policy attiva?)")                                       
      338 +                print(f"  {YELLOW}!{RESET} {agent_id}  →  binding {b['status']} (role policy attiva?)")                
      339              else:
      340                  ok(f"{agent_id}  →  binding non trovato (agente già esistente?)")
      341  

● Ora faccio un test sintattico e verifico che il file sia importabile:

● Bash(python -c "import ast; ast.parse(open('bootstrap.py').read()); print('OK syntax')")                                           
  ⎿  OK syntax
                                                                                                                                     
● bootstrap.py è aggiornato. Il nuovo flusso è:                                                                                      
                                                                                                                                     
  1. [1/4] Role policy — crea role:buyer → role:supplier con admin secret, prima degli agenti                                        
  2. [2/4] Org — join + approvazione admin (invariato)                               
  3. [3/4] Agenti — registra con role=buyer/role=supplier → auto-binding scatta al momento della registrazione                       
  4. [4/4] Verifica — controlla che i binding siano approved e stampa lo scope                                                       
                                                                              
