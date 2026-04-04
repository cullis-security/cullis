[nix-shell:~/projects/agent-trust]$ ./run.sh
INFO:     Will watch for changes in these directories: ['/home/daenaihax/projects/agent-trust']
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
INFO:     Started reloader process [24594] using WatchFiles
INFO:     Started server process [24603]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     127.0.0.1:49444 - "GET /health HTTP/1.1" 200 OK
INFO:     127.0.0.1:49444 - "POST /registry/orgs HTTP/1.1" 201 Created
INFO:     127.0.0.1:49444 - "POST /registry/orgs HTTP/1.1" 201 Created
INFO:     127.0.0.1:49444 - "POST /registry/orgs/manufacturer/certificate HTTP/1.1" 200 OK
INFO:     127.0.0.1:49444 - "POST /registry/orgs/buyer/certificate HTTP/1.1" 200 OK
INFO:     127.0.0.1:49444 - "POST /registry/agents HTTP/1.1" 201 Created
INFO:     127.0.0.1:49444 - "POST /registry/agents HTTP/1.1" 201 Created
INFO:     127.0.0.1:49444 - "POST /registry/bindings HTTP/1.1" 201 Created
INFO:     127.0.0.1:49444 - "POST /registry/bindings/1/approve HTTP/1.1" 200 OK
INFO:     127.0.0.1:49444 - "POST /registry/bindings HTTP/1.1" 201 Created
INFO:     127.0.0.1:49444 - "POST /registry/bindings/2/approve HTTP/1.1" 200 OK
INFO:     127.0.0.1:49444 - "POST /policy/rules HTTP/1.1" 201 Created
INFO:     127.0.0.1:55812 - "POST /registry/agents HTTP/1.1" 409 Conflict
INFO:     127.0.0.1:55812 - "POST /auth/token HTTP/1.1" 200 OK
INFO:     ('127.0.0.1', 55818) - "WebSocket /broker/ws" [accepted]
INFO:     connection open
INFO:     127.0.0.1:55812 - "GET /broker/sessions?status=active HTTP/1.1" 200 OK
INFO:     127.0.0.1:55812 - "GET /broker/sessions?status=pending HTTP/1.1" 200 OK
INFO:     127.0.0.1:55820 - "POST /registry/agents HTTP/1.1" 409 Conflict
INFO:     127.0.0.1:55820 - "POST /auth/token HTTP/1.1" 200 OK
INFO:     127.0.0.1:55820 - "GET /broker/sessions HTTP/1.1" 200 OK
INFO:     127.0.0.1:55820 - "POST /broker/sessions HTTP/1.1" 201 Created
INFO:     127.0.0.1:55820 - "GET /broker/sessions HTTP/1.1" 200 OK
INFO:     127.0.0.1:55812 - "POST /broker/sessions/db25c845-3a85-4292-a344-0c1893be0de9/accept HTTP/1.1" 200 OK
LLM judge risposta malformata: Expecting value: line 1 column 1 (char 0)
INFO:     127.0.0.1:39946 - "POST /broker/sessions/db25c845-3a85-4292-a344-0c1893be0de9/messages HTTP/1.1" 202 Accepted
