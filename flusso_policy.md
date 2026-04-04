Flusso nuovo:                                                                                                                      
   
  # 1. Admin — una volta sola, definisce le policy di ruolo nel broker                                                               
  python policy.py                                                                                                                   
  # → crea policy network-level: role:buyer ↔ role:supplier                                                                          
                                                                                                                                     
  # 2. Org — ogni org che si unisce                                                                                                  
  python join.py                                                                                                                     
  # → genera CA locale, registra org nel broker, aspetta approvazione admin                                                          
                                                                                                                                     
  # 3. Agente — dopo che l'org è approvata
  python join_agent.py --org pazzo --name compratore --role buyer                                                                    
  # → genera keypair + cert (firmato dalla CA locale dell'org)                                                                       
  # → registra agente nel broker con il ruolo                                                                                        
  # → broker applica automaticamente le policy del ruolo "buyer"                                                                     
  # → salva config in certs/pazzo/compratore/ (cert + key)                                                                           
                                                                                                                                     
  # 4. L'utente ha già il suo buyer.py                                                                                               
  python buyer.py --config certs/pazzo/compratore/                                                                                   
  # → autenticazione x509/SPIFFE → JWT → business logic                                                                              
                                                                                                                                     
  Cambiamenti al broker:
  - policy.py crea policy per ruolo (role:buyer → role:supplier), non per coppia di org                                              
  - Il broker quando riceve la registrazione di un agente con role=buyer cerca la policy del ruolo e la applica automaticamente      
  (binding + session policy)                                                                                                   
                                                                                                                                     
  buyer.py e manufacturer.py esistono già — scritti dall'utente, prendono solo --config con il percorso ai certificati.
                                                                                                                                     
  Ho capito bene? Un dubbio: la CA dell'org (la chiave privata) serve in locale per firmare il cert dell'agente in join_agent.py.    
  Questo va bene o preferisci che sia il broker a firmare (e quindi la CA key la invia al broker)? 
