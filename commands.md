# Agent Trust Network — Comandi

## Flusso completo (primo avvio o dopo reset)

### 1. Reset e setup broker
```bash
./reset.sh
python generate_certs.py
./run.sh
```

### 2. Admin in ascolto (terminale dedicato)
```bash
python admin.py --secret <ADMIN_SECRET>
```

### 3. Policy di rete (una volta sola)
```bash
python policy.py
# → inserisci admin secret
# → Ruolo initiator: buyer
# → Ruolo target: supplier
# → Capabilities: (invio = tutte)
# → Max sessioni: (invio = illimitato)
# → Policy ID: (invio = default)
```

### 4. Registrazione org + agente (una per org)
```bash
python join.py
# → Broker URL: http://localhost:8000
# → Org ID: acmebuyer
# → Password org: <scegli>
# → Agent name: buyer
# → Role: 2  (buyer)
# admin.py approva automaticamente
# → salva certs/acmebuyer/acmebuyer__buyer.env

python join.py
# → Org ID: italmetal
# → Password org: <scegli>
# → Agent name: supplier
# → Role: 1  (supplier)
# admin.py approva automaticamente
# → salva certs/italmetal/italmetal__supplier.env
```

### 5. Avvia gli agenti (terminali separati)
```bash
# Prima il responder (deve essere in ascolto)
python agents/manufacturer.py --config certs/italmetal/italmetal__supplier.env

# Poi l'initiator
python agents/buyer.py --config certs/acmebuyer/acmebuyer__buyer.env
```

---

## Aggiungere un agente extra a un'org già approvata
```bash
python join_agent.py --org acmebuyer --name procurement2 --role buyer \
                     --capabilities order.read,order.write
# → salva certs/acmebuyer/procurement2/agent.env

python agents/buyer.py --config certs/acmebuyer/procurement2/agent.env
```

---

## Test automatici
```bash
pytest tests/ -v

# File singolo
pytest tests/test_auth.py -v

# Test singolo
pytest tests/test_auth.py::test_nome -v
```
