Hai spiegato benissimo il punto: stai separando l’identità esterna del workload dal contesto utente interno al dominio. Verifico solo nel draft i pezzi su context propagation e AI intermediaries, così ti dico se questa scelta è coerente o dove va rifinita.

Thought for 14s

Sì, ti sei spiegato bene. E questa è una distinzione molto importante: tu vuoi che fuori dal dominio si veda solo l’identità del workload, mentre l’identità dell’utente resta interna al dominio. Questa impostazione è coerente con il fatto che WIMSE separa workload identity e security context, e riconosce che il security context può includere informazioni sull’utente e altri attributi usati per authorization, accounting e auditing.

Detta in modo semplice, nel tuo modello ci sono due livelli distinti.

Livello esterno, verso il broker o fuori dal trust domain
Qui il broker deve sapere solo:

questo è agent_planner
appartiene a OrgA
è autenticato crittograficamente
ha certe capability/policy di alto livello nel network

Questo è workload identity + network-level authorization.

Livello interno, dentro OrgA
Qui OrgA sa:

l’utente è Alice
Alice può usare agent_planner
Alice può fare solo search_docs
Alice non può fare request_info

Questo è end-user context + internal authorization.

Questa separazione ha senso anche dal punto di vista privacy: il broker non ha bisogno di conoscere Alice per autenticare agent_planner. Il draft WIMSE dice che il security context può includere user information, ma non dice che ogni intermediario debba conoscere sempre tutta l’identità utente; anzi, nei sistemi con AI intermediaries il contesto va propagato in modo controllato e scoped lungo workflow multi-step.

Quindi la tua idea, formulata bene, è questa:

Il broker autentica e autorizza il workload, non l’utente finale.
L’utente finale viene autorizzato dentro il trust domain dell’organizzazione.

Questo è un modello molto sensato.

Facciamo il tuo esempio con i due strati separati.

Dentro OrgA

Alice chiama agent_planner.

OrgA applica policy interne:

Alice può usare agent_planner
Alice può fare solo search_docs

Questa parte è interna.
Qui il contesto potrebbe essere:

user = Alice
action = search_docs
org = OrgA
Fuori da OrgA, verso il broker

Quando agent_planner si presenta al broker, il broker non vede:

Alice
il suo ruolo preciso
i dettagli della sua richiesta interna

Il broker vede:

spiffe://orga.example/orga/agent_planner
firmato o attestato da OrgA
proof of possession della chiave dell’agente
eventuali capability di rete consentite, tipo search_docs, request_info

Questa parte è esterna.
Qui il broker sta decidendo qualcosa come:

“Questo workload di OrgA può usare questa parte del network?”

non:

“Alice personalmente può fare questa cosa?”

Ed è qui la differenza chiave tra policy interna utente→agente e policy esterna agente→network.

Quindi quando dici:

“il broker sa che agent_planner è legato a OrgA e tramite le policy può fare solo search_docs e request_info, ma internamente Alice può fare solo search_docs”

questa è una struttura corretta. In pratica hai:

policy interna: Alice -> agent_planner -> search_docs
policy esterna: agent_planner@OrgA -> network -> {search_docs, request_info}

La cosa importante però è non chiamare tutto “security context” allo stesso modo.

Io lo separerei così:

1. Workload identity

Chi è il chiamante esterno?

agent_planner
appartenente a OrgA
identificato con SPIFFE ID
autenticato con chiave/PoP
2. Internal user context

Chi sta usando l’agente dentro OrgA?

Alice
ruolo
tenant
limiti interni
3. External propagated context, se mai lo mandi

Che cosa OrgA vuole rivelare fuori?
Per esempio:

“questa richiesta è user-initiated”
“classification=internal”
“purpose=search_docs”

ma senza dire che l’utente è Alice.

Questo terzo pezzo è interessante perché è probabilmente il modo giusto di collegarti a WIMSE senza violare la privacy: non propaghi per forza l’identità personale, ma puoi propagare attributi minimizzati del contesto. Il draft tratta proprio security context propagation come informazione utile per authorization, accounting e auditing, e la sezione sugli AI intermediaries sottolinea che questi sistemi operano per conto di un principal upstream in workflow multi-step.

Quindi la risposta secca è:

No, non serve che il broker sappia che è Alice.
Può sapere solo che:

il caller è agent_planner di OrgA
il caller ha una certa autorizzazione nel network
opzionalmente la richiesta porta un contesto minimizzato o pseudonimizzato

Questo è anche più elegante architetturalmente.

La parte delicata è questa: se il broker autorizza agent_planner a fare request_info, ma internamente Alice non può, allora devi garantire che agent_planner faccia enforcement interno prima di uscire dal dominio. Altrimenti il broker vede un workload autorizzato e non può distinguere se la richiesta concreta è coerente con i limiti di Alice. Quindi il punto critico del tuo sistema è:

l’uscita dal trust domain deve essere subordinata a una decisione interna che combina utente + agente + azione.

Se questa decisione è fatta bene, il tuo modello regge molto bene.

La formulazione “da draft” per il tuo disegno sarebbe qualcosa del genere:

The broker authenticates the workload identity of agent_planner as a workload belonging to OrgA.
End-user authorization remains inside OrgA’s trust domain.
Only workload identity and minimal network-relevant authorization are exposed externally; user-specific context is enforced internally and need not be disclosed to the broker.

Questa frase è coerente con la separazione WIMSE tra workload identity e security context, e con il fatto che gli AI intermediaries agiscono per conto di un principal upstream lungo catene multi-step.

Il punto dove puoi diventare ancora più forte è introdurre una distinzione esplicita tra:

capability massima del workload nel network
effective permission della singola richiesta, derivata internamente da utente + policy

Per esempio:

agent_planner ha capability di rete: {search_docs, request_info}
richiesta corrente di Alice: {search_docs}

Questa è una separazione molto pulita.

Se vuoi, nel prossimo messaggio ti trasformo esattamente il tuo modello in un diagramma concettuale con 5 blocchi: user, org policy, agent identity, broker trust, downstream authorization.


Modello a 2 token

Io farei così:

1. Access token di sessione

Serve a dire:

chi è il workload
a quale org appartiene
quali capability massime ha nel network

Questo è il token “base”, simile a quello che già emetti oggi. Il tuo broker già lavora in questa direzione con identity x509/SPIFFE + binding + policy.

2. Delegation Context Token

Serve a dire:

questa specifica richiesta è stata originata su delega
con quale scope effettivo
con quale scopo
con quale subject pseudonimizzato
con quale chain/transaction id

È questo il token che realizza davvero context propagation. WIMSE dice che il security context viene propagato workload-to-workload usando token, e può essere bound al workload o alla transazione.

Claim set concreto

Ti suggerisco un token JWT firmato da OrgA o dal broker come trust service.
Io, nel tuo caso, partirei con firma broker per semplicità operativa.

Claim minimi
Claim 1 — iss

Chi ha emesso il token.

Esempio:

"iss": "https://broker.atn.local"

Serve per trust e validation standard.

Claim 2 — aud

A chi è destinato.

Esempio:

"aud": "spiffe://orgb/supplier-agent"

Oppure:

"aud": "orgB"

Meglio target specifico quando possibile. WIMSE insiste sul binding del contesto a uno specifico target/workload quando serve.

Claim 3 — client_id oppure act

Chi è il workload che sta materialmente facendo la chiamata.

Esempio:

"client_id": "spiffe://orga/agents/agent_planner"

oppure, più ricco:

"act": {
  "sub": "spiffe://orga/agents/agent_planner"
}

Questo separa nettamente il caller workload dal delegante.

Claim 4 — sub

Il principal delegante, ma non in chiaro.

Esempio:

"sub": "urn:atn:userctx:7f4c2a91"

oppure:

"sub": "urn:atn:systemctx:erp-run-20260330"

Quindi fuori dal dominio non mandi “alice@orga.com
”, ma un identificatore opaco o pseudonimizzato. Questo è molto coerente con il tuo modello di external propagated context minimizzato e con la generalizzazione cross-boundary di WIMSE.

Claim 5 — scope

Lo scope effettivo della singola richiesta, non la capability massima del workload.

Esempio:

"scope": "search_docs"

oppure:

"scope": "catalog.search order.read"

Questo è il punto più importante del tuo design: distinguere tra capability massima del workload e permission effettiva della richiesta. Lo hai già formulato bene nel tuo security_context.md.

Claim 6 — purpose

Perché questa richiesta esiste.

Esempio:

"purpose": "search_docs"

oppure:

"purpose": "supplier-discovery"

Non è uno standard OAuth classico, ma architetturalmente è molto utile per audit e policy. Nel tuo modello il purpose è uno degli attributi giusti da propagare fuori senza esporre il dettaglio utente.

Claim 7 — txn oppure jti

Identificatore univoco della transazione o della chain.

Esempio:

"txn": "7d7b8c6e-3ef9-4e8d-a9b9-ff3d6f54b301"

e anche:

"jti": "1c51c8f0-0b8f-4b4f-8e7b-b4f0f5d2cc77"

Questo serve a replay protection, correlation e audit. WIMSE parla esplicitamente di binding del contesto a una o più transaction e di request correlation.

Claim 8 — exp + iat

Scadenza molto breve.

Esempio:

"iat": 1774887000,
"exp": 1774887060

60 secondi, 120 al massimo.
Più il token è “delegated/scoped”, più dev’essere corto. Questo è allineato sia a WIMSE sia al draft AI auth, che insiste su credenziali e token short-lived e downscoped.

Claim opzionali molto utili
delegation_type

Per distinguere:

"delegation_type": "user"

oppure:

"delegation_type": "system"

oppure:

"delegation_type": "agent"

Molto utile quando avrai agent-to-agent multi-hop.

chain

Per tracciare la caller chain.

Esempio:

"chain": [
  "userctx:7f4c2a91",
  "spiffe://orga/agents/agent_planner",
  "spiffe://orga/agents/research_subagent"
]

Anche se all’inizio puoi farne a meno e usare solo parent_txn.

cls

Classificazione del contesto.

Esempio:

"cls": "internal"

oppure:

"cls": "customer-data-minimized"
Esempio completo
{
  "iss": "https://broker.atn.local",
  "aud": "spiffe://orgb/agents/supplier-agent",
  "client_id": "spiffe://orga/agents/agent_planner",
  "sub": "urn:atn:userctx:7f4c2a91",
  "delegation_type": "user",
  "scope": "search_docs",
  "purpose": "supplier-discovery",
  "txn": "7d7b8c6e-3ef9-4e8d-a9b9-ff3d6f54b301",
  "jti": "1c51c8f0-0b8f-4b4f-8e7b-b4f0f5d2cc77",
  "iat": 1774887000,
  "exp": 1774887060
}

Traduzione semantica:

il workload agent_planner di OrgA sta chiamando supplier-agent su delega di un subject interno pseudonimizzato, con scope effettivo search_docs, per la transazione X, per uno scopo preciso, per un tempo molto breve.

Regole di enforcement

Per far funzionare bene questo modello, io metterei 4 regole nette.

Regola 1

Il broker continua a validare il workload identity layer:

cert / SPIFFE
org
binding
capability massima

Questo ce l’hai già quasi tutto.

Regola 2

Il broker o il downstream valida anche il delegation context token:

firma
audience
expiry
scope
txn id
coerenza con il caller
Regola 3

Lo scope del delegation token deve essere sempre un sottoinsieme delle capability massime del workload.

Quindi:

workload max: {search_docs, request_info}
request effettiva: {search_docs}

mai il contrario. Questo è il cuore del tuo modello.

Regola 4

A ogni hop, il token va re-scoped e re-bound.

WIMSE è esplicito: negli scenari AI-to-AI, ogni hop deve fare scope and re-bind del security context per evitare che la chain estenda autorità oltre il consentito.

Come si traduce nel tuo caso
Flusso
Step A — interno OrgA

Alice chiama agent_planner.

OrgA valuta internamente:

Alice può usare agent_planner
Alice può fare solo search_docs
Step B — emissione token

OrgA o broker emette il Delegation Context Token con:

sub = urn:atn:userctx:...
scope = search_docs
purpose = supplier-discovery
Step C — uscita dal dominio

agent_planner si autentica verso broker con il suo SPIFFE/x509, e allega anche il delegation token.

Step D — downstream

Il broker o l’agente downstream vede:

workload reale
contesto delegato minimizzato
scope effettivo
transaction id

ma non vede Alice in chiaro.

Questo è esattamente il pattern che volevi ottenere.

Cosa non farei

Non farei subito:

full OAuth identity chaining cross-domain
transaction tokens completi stile draft OAuth
actor chain complessa con 4 livelli
esposizione dell’identità utente reale al broker

Sono step successivi. La tua architettura oggi è più adatta a partire con un mini delegated context token e poi evolvere. La tua roadmap stessa riconosce che oggi manca soprattutto context propagation / user delegation chain, non tutta la macchina OAuth completa.

Versione MVP consigliata

Per partire davvero bene, io implementerei solo questi claim:

iss
aud
client_id
sub opaco
scope
purpose
txn
exp

Basta questo per fare già:

user delegation minimizzata
context propagation
audit chain
downscoping
privacy cross-domain
La frase architetturale che puoi usare

ATN authenticates the workload identity at network level, while delegated end-user context remains governed within the originating trust domain and is propagated externally only as a minimized, scoped, short-lived delegation context bound to the acting workload and transaction.
