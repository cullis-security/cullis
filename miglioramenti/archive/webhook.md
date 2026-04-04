from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class AgentRef(BaseModel):
    agent_id: str

class SessionRequest(BaseModel):
    session_id: str
    initiator: AgentRef
    target: AgentRef
    requested_capabilities: list[str]

# Il prefisso della tua organizzazione per capire se l'agente è tuo
MY_ORG_PREFIX = "spiffe://atn.local/org-B/"

# --- 1. MATRICE INBOUND (Chi può chiamare i TUOI agenti) ---
INBOUND_RULES = {
    # Al tuo Agente B1 può accedere l'Agente A1
    "spiffe://atn.local/org-B/agente-B1": {
        "spiffe://atn.local/org-A/agente-A1": {"leggi_dati", "compito_condiviso_1"}
    }
}

# --- 2. MATRICE OUTBOUND (Chi possono chiamare i TUOI agenti) ---
OUTBOUND_RULES = {
    # Il tuo Agente B1 ha il permesso di uscire e chiamare l'Agente A2
    "spiffe://atn.local/org-B/agente-B1": {
        "spiffe://atn.local/org-A/agente-A2": {"invia_report", "notifica_completamento"}
    }
}

@app.post("/webhook/atn-policy")
async def evaluate_agent_session(request: SessionRequest):
    
    initiator = request.initiator.agent_id
    target = request.target.agent_id
    capabilities = set(request.requested_capabilities)
    
    # CASO A: OUTBOUND (Il TUO agente sta cercando di uscire)
    if initiator.startswith(MY_ORG_PREFIX):
        
        # 1. Il tuo agente ha delle regole di uscita definite?
        if initiator not in OUTBOUND_RULES:
            return {"decision": "deny", "reason": "Outbound: Il tuo agente non ha permessi per comunicare all'esterno."}
            
        allowed_targets = OUTBOUND_RULES[initiator]
        
        # 2. Il tuo agente ha il permesso di chiamare QUESTO specifico target esterno?
        if target not in allowed_targets:
            return {"decision": "deny", "reason": f"Outbound: Il tuo {initiator} non può chiamare {target}."}
            
        # 3. Sta usando le capacità corrette in uscita?
        allowed_caps = allowed_targets[target]
        if not capabilities.issubset(allowed_caps):
             return {"decision": "deny", "reason": "Outbound: Capacità non permesse in uscita verso questo target."}
             
        # Se passano i controlli, tu autorizzi l'uscita. 
        # (Il Broker ATN chiamerà poi il webhook di Jorge per chiedere se lui accetta l'entrata).
        return {"decision": "allow", "reason": "Outbound autorizzato dalle tue policy."}


    # CASO B: INBOUND (Un agente ESTERNO sta cercando di chiamare il tuo)
    elif target.startswith(MY_ORG_PREFIX):
        
        # 1. Il tuo agente espone servizi all'esterno?
        if target not in INBOUND_RULES:
            return {"decision": "deny", "reason": "Inbound: Agente target sconosciuto o privato."}
            
        allowed_initiators = INBOUND_RULES[target]
        
        # 2. L'esterno è autorizzato a chiamare il tuo agente?
        if initiator not in allowed_initiators:
            return {"decision": "deny", "reason": f"Inbound: {initiator} non è autorizzato a contattare {target}."}
            
        # 3. Sta chiedendo le capacità corrette in entrata?
        allowed_caps = allowed_initiators[initiator]
        if not capabilities.issubset(allowed_caps):
             return {"decision": "deny", "reason": "Inbound: Capacità non permesse in entrata."}
             
        return {"decision": "allow", "reason": "Inbound autorizzato dalle tue policy."}


    # CASO C: Nessuno dei due agenti appartiene alla tua Org (Non dovrebbe mai succedere se il Broker ATN funziona bene)
    else:
         return {"decision": "deny", "reason": "Né l'initiator né il target appartengono a questa organizzazione."}
