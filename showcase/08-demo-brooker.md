[nix-shell:~/projects/agent-trust]$ ./run.sh
INFO:     Will watch for changes in these directories: ['/home/daenaihax/projects/agent-trust']
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
INFO:     Started reloader process [23855] using WatchFiles
INFO:     Started server process [23864]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     127.0.0.1:44796 - "GET /health HTTP/1.1" 200 OK
INFO:     127.0.0.1:44800 - "POST /onboarding/join HTTP/1.1" 202 Accepted
INFO:     127.0.0.1:44812 - "GET /registry/orgs/manufacturer HTTP/1.1" 200 OK
INFO:     127.0.0.1:45502 - "GET /registry/orgs/manufacturer HTTP/1.1" 200 OK
INFO:     127.0.0.1:45516 - "POST /admin/orgs/manufacturer/approve HTTP/1.1" 200 OK
INFO:     127.0.0.1:45520 - "GET /registry/orgs/manufacturer HTTP/1.1" 200 OK
INFO:     127.0.0.1:45522 - "POST /registry/bindings HTTP/1.1" 201 Created
INFO:     127.0.0.1:45532 - "POST /registry/bindings/1/approve HTTP/1.1" 200 OK
INFO:     127.0.0.1:52576 - "POST /registry/agents HTTP/1.1" 201 Created
INFO:     127.0.0.1:52576 - "POST /auth/token HTTP/1.1" 200 OK
INFO:     127.0.0.1:52576 - "GET /broker/sessions?status=active HTTP/1.1" 200 OK
INFO:     ('127.0.0.1', 52588) - "WebSocket /broker/ws" [accepted]
INFO:     connection open
INFO:     127.0.0.1:52576 - "GET /broker/sessions?status=pending HTTP/1.1" 200 OK
INFO:     connection closed
^CINFO:     Shutting down
INFO:     Waiting for application shutdown.
INFO:     Application shutdown complete.
INFO:     Finished server process [23864]
INFO:     Stopping reloader process [23855]
(.venv) O

