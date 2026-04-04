[nix-shell:~/projects/agent-trust]$ python generate_certs.py

Agent Trust Network — Broker Certificate Generation

[1/1] Broker CA
  ✓  broker CA generated

Broker CA ready in /home/daenaihax/projects/agent-trust/certs

  certs/broker-ca.pem
  certs/broker-ca-key.pem

Organizations generate their own certificates with join.py:
  python join.py --broker http://localhost:8000 \
                 --org-id <org> --display-name <name> \
                 --secret <secret> --agents <org>::<agent>
(.venv)
