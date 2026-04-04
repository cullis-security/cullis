[nix-shell:~/projects/agent-trust]$ python join.py

╔══════════════════════════════════════════╗
║   Agent Trust Network — Join Wizard      ║
╚══════════════════════════════════════════╝
Questo wizard registra la tua organizzazione nel network TrustLink.
Verranno generati i certificati x509 e inviata la join request.

  Broker URL [http://localhost:8000]: http://localhost:8000
  Org ID (es. acme-corp): manufacturer
  Nome organizzazione (es. ACME Corporation) [manufacturer]: ChipFactory
  Password org (usata per approvare i binding): 
  Email di contatto per TrustLink: admin@admin.demo      

  Agenti da registrare (formato: manufacturer::nome-agente)
  Puoi aggiungerne più di uno separati da virgola.
  Agenti [manufacturer::agent]: manufacturer::sales-agent

Riepilogo:
  Broker:       http://localhost:8000
  Org ID:       manufacturer
  Nome:         ChipFactory
  Contatto:     admin@admin.demo
  Agenti:       manufacturer::sales-agent

  Confermi? [s/N]: s

[1/4] Verifica connessione al broker
  ✓ Broker raggiungibile

[2/4] Generazione certificati x509
  ✓ CA generata: certs/manufacturer/ca.pem
  ✓ Certificato agente: certs/manufacturer/manufacturer__sales-agent.pem

[3/4] Invio join request a TrustLink
  ✓ Join request inviata — stato: pending
  → Richiesta ricevuta. In attesa di approvazione da parte di TrustLink.

[4/5] Salvataggio configurazione agenti
  ✓ Config agente: certs/manufacturer/manufacturer__sales-agent.env

In attesa di approvazione TrustLink...
(TrustLink deve approvare la tua richiesta. Max 5 minuti.)

  L'admin di TrustLink deve approvare la tua richiesta:
  curl -s -X POST http://localhost:8000/admin/orgs/manufacturer/approve \
       -H 'x-admin-secret: <ADMIN_SECRET>'

  ✓ Organizzazione 'manufacturer' approvata!

[5/5] Binding agenti
  ✓ Binding approvato: manufacturer::sales-agent

Sei nel network. Avvia il tuo agente:
  python agents/client.py --config certs/manufacturer/manufacturer__sales-agent.env

(.venv) 
