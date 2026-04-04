[nix-shell:~/projects/agent-trust]$ python bootstrap.py

Agent Trust Network — Bootstrap
Broker: http://localhost:8000

[0/5] x509 Certificates
  → Certificates already present (already present — skip)

[1/5] Organizations (join + approve)
  ✓ Join request sent: manufacturer (ChipFactory)
  ✓ Org approved: manufacturer
  ✓ Join request sent: buyer (ElectroStore)
  ✓ Org approved: buyer

[3/5] Agents
  ✓ Agent registered: manufacturer::sales-agent
  ✓ Agent registered: buyer::procurement-agent

[4/5] Bindings
  ✓ Binding created and approved: manufacturer::sales-agent → manufacturer scope=['order.read', 'order.write']
  ✓ Binding created and approved: buyer::procurement-agent → buyer scope=['order.read', 'order.write']

[5/5] Session policy
  ✓ Session policy created: buyer::session-v1 (buyer → manufacturer)

────────────────────────────────────────
Summary
  Created:  8  join:manufacturer, approved:manufacturer, join:buyer, approved:buyer, agent:manufacturer::sales-agent, agent:buyer::procurement-agent, binding:manufacturer::sales-agent, binding:buyer::procurement-agent, policy:buyer::session-v1
  Skipped:  0  —

Bootstrap complete. You can now start the agents:

  ./agent.sh --config agents/manufacturer.env
  ./agent.sh --config agents/buyer.env

(.venv)

---

## External onboarding via join.py

For organizations joining from outside the lab:

[nix-shell:~/projects/agent-trust]$ python join.py

╔══════════════════════════════════════════╗
║   Agent Trust Network — Join Wizard      ║
╚══════════════════════════════════════════╝
Questo wizard registra la tua organizzazione nel network TrustLink.
Verranno generati i certificati x509 e inviata la join request.

  Broker URL [http://localhost:8000]: http://localhost:8000
  Org ID (es. acme-corp): acme-corp
  Nome organizzazione (es. ACME Corporation) [acme-corp]: ACME Corporation
  Password org (usata per approvare i binding):
  Email di contatto per TrustLink: admin@acme.com

  Agenti da registrare (formato: acme-corp::nome-agente)
  Puoi aggiungerne più di uno separati da virgola.
  Agenti [acme-corp::agent]: acme-corp::procurement-agent

Riepilogo:
  Broker:       http://localhost:8000
  Org ID:       acme-corp
  Nome:         ACME Corporation
  Contatto:     admin@acme.com
  Agenti:       acme-corp::procurement-agent

  Confermi? [s/N]: s

[1/5] Verifica connessione al broker
  ✓ Broker raggiungibile

[2/5] Generazione certificati x509
  ✓ CA generata: certs/acme-corp/ca.pem
  ✓ Certificato agente: certs/acme-corp/acme-corp__procurement-agent.pem

[3/5] Invio join request a TrustLink
  ✓ Join request inviata — stato: pending
  → Richiesta ricevuta. In attesa di approvazione da parte di TrustLink.

[4/5] Salvataggio configurazione agenti
  ✓ Config agente: certs/acme-corp/acme-corp__procurement-agent.env

In attesa di approvazione TrustLink...
(TrustLink deve approvare la tua richiesta. Max 5 minuti.)

  L'admin di TrustLink deve approvare la tua richiesta:
  curl -s -X POST http://localhost:8000/admin/orgs/acme-corp/approve \
       -H 'x-admin-secret: <ADMIN_SECRET>'

  ✓ Organizzazione 'acme-corp' approvata!

[5/5] Binding agenti
  ✓ Binding approvato: acme-corp::procurement-agent

Sei nel network. Avvia il tuo agente:
  python agents/client.py --config certs/acme-corp/acme-corp__procurement-agent.env
