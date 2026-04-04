Il cambiamento è medio — concentrato in 4 file, scope ben definito.                                                   
                                                            
  Broker (app/broker/router.py) — piccolo:                                                                              
  - Rimuove il check injection (~5 righe)                   
  - La verifica firma sul plaintext cade — il broker non può più verificarla perché non vede il contenuto. Può invece   
  verificare la firma sul ciphertext (integrità di trasporto: "questo agente ha inviato questo blob cifrato")        
                                                                                                                        
  Agent (agents/sdk.py) — medio:
  - send_message(): cifra il payload prima di inviare                                                                   
  - Path di ricezione (poll, WebSocket): decifra dopo aver ricevuto                                                     
  - _process_received_message(): aggiunge injection detection sul plaintext decifrato, prima di passarlo all'LLM        
                                                                                                                        
  Modelli messaggi — piccolo:                                                                                           
  - Il campo payload diventa un blob cifrato: {encrypted_key, ciphertext, iv} invece di {text: "..."}                   
                                                                                                                        
  Nuovo endpoint — piccolo:                                                                                             
  - GET /registry/agents/{agent_id}/public-key — il mittente recupera la chiave pubblica del destinatario per cifrare.  
  La chiave è già in DB (cert salvato al login).                                                                        
                                                                                                                        
  ---                                                                                                                   
  La parte delicata è la firma. Oggi il broker verifica la firma sul plaintext. Con E2E la proposta è:                  
                                                                                                                        
  sign(plaintext) → encrypt(plaintext + firma) → broker forwarda                                                        
                                                → destinatario decifra → verifica firma                                 
                                                                                                                        
  Il broker non verifica più nulla sul contenuto — solo che il token JWT è valido e la policy è rispettata. La          
  non-repudiation rimane tra i due agenti, non passa più per il broker.                                                 
                                                                                                                        
  ---                                                       
  File che cambiano: app/broker/router.py, agents/sdk.py, app/broker/models.py, un nuovo endpoint nel registry. I test
  di firma e injection vanno aggiornati. 
