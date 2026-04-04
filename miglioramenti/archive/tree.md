tree -L 4
.
├── admin.py
├── agents
│   ├── banca_a.env
│   ├── banca_b.env
│   ├── buyer.env
│   ├── buyer.py
│   ├── client.py
│   ├── DEMO.md
│   ├── manufacturer.env
│   ├── manufacturer.py
│   ├── __pycache__
│   │   └── sdk.cpython-311.pyc
│   └── sdk.py
├── agent.sh
├── app
│   ├── auth
│   │   ├── __init__.py
│   │   ├── jti_blacklist.py
│   │   ├── jwt.py
│   │   ├── message_signer.py
│   │   ├── models.py
│   │   ├── __pycache__
│   │   │   ├── __init__.cpython-311.pyc
│   │   │   ├── jti_blacklist.cpython-311.pyc
│   │   │   ├── jwt.cpython-311.pyc
│   │   │   ├── message_signer.cpython-311.pyc
│   │   │   ├── models.cpython-311.pyc
│   │   │   ├── revocation.cpython-311.pyc
│   │   │   ├── router.cpython-311.pyc
│   │   │   └── x509_verifier.cpython-311.pyc
│   │   ├── revocation.py
│   │   ├── router.py
│   │   └── x509_verifier.py
│   ├── broker
│   │   ├── db_models.py
│   │   ├── __init__.py
│   │   ├── models.py
│   │   ├── persistence.py
│   │   ├── __pycache__
│   │   │   ├── db_models.cpython-311.pyc
│   │   │   ├── __init__.cpython-311.pyc
│   │   │   ├── models.cpython-311.pyc
│   │   │   ├── persistence.cpython-311.pyc
│   │   │   ├── router.cpython-311.pyc
│   │   │   ├── session.cpython-311.pyc
│   │   │   └── ws_manager.cpython-311.pyc
│   │   ├── router.py
│   │   ├── session.py
│   │   └── ws_manager.py
│   ├── config.py
│   ├── db
│   │   ├── audit.py
│   │   ├── database.py
│   │   ├── __init__.py
│   │   └── __pycache__
│   │       ├── audit.cpython-311.pyc
│   │       ├── database.cpython-311.pyc
│   │       └── __init__.cpython-311.pyc
│   ├── e2e_crypto.py
│   ├── __init__.py
│   ├── injection
│   │   ├── detector.py
│   │   ├── __init__.py
│   │   ├── patterns.py
│   │   └── __pycache__
│   │       ├── detector.cpython-311.pyc
│   │       ├── __init__.cpython-311.pyc
│   │       └── patterns.cpython-311.pyc
│   ├── main.py
│   ├── onboarding
│   │   ├── __init__.py
│   │   ├── __pycache__
│   │   │   ├── __init__.cpython-311.pyc
│   │   │   └── router.cpython-311.pyc
│   │   └── router.py
│   ├── policy
│   │   ├── engine.py
│   │   ├── __init__.py
│   │   ├── models.py
│   │   ├── __pycache__
│   │   │   ├── engine.cpython-311.pyc
│   │   │   ├── __init__.cpython-311.pyc
│   │   │   ├── models.cpython-311.pyc
│   │   │   ├── router.cpython-311.pyc
│   │   │   └── store.cpython-311.pyc
│   │   ├── router.py
│   │   └── store.py
│   ├── __pycache__
│   │   ├── config.cpython-311.pyc
│   │   ├── e2e_crypto.cpython-311.pyc
│   │   ├── __init__.cpython-311.pyc
│   │   ├── main.cpython-311.pyc
│   │   └── spiffe.cpython-311.pyc
│   ├── rate_limit
│   │   ├── __init__.py
│   │   ├── limiter.py
│   │   └── __pycache__
│   │       ├── __init__.cpython-311.pyc
│   │       └── limiter.cpython-311.pyc
│   ├── registry
│   │   ├── binding_router.py
│   │   ├── binding_store.py
│   │   ├── __init__.py
│   │   ├── models.py
│   │   ├── org_router.py
│   │   ├── org_store.py
│   │   ├── __pycache__
│   │   │   ├── binding_router.cpython-311.pyc
│   │   │   ├── binding_store.cpython-311.pyc
│   │   │   ├── __init__.cpython-311.pyc
│   │   │   ├── models.cpython-311.pyc
│   │   │   ├── org_router.cpython-311.pyc
│   │   │   ├── org_store.cpython-311.pyc
│   │   │   ├── router.cpython-311.pyc
│   │   │   └── store.cpython-311.pyc
│   │   ├── router.py
│   │   └── store.py
│   └── spiffe.py
├── bootstrap.py
├── certs
│   ├── acmebuyer
│   │   ├── acmebuyer__buyer.env
│   │   ├── acmebuyer__buyer-key.pem
│   │   ├── acmebuyer__buyer.pem
│   │   ├── ca-key.pem
│   │   └── ca.pem
│   ├── broker-ca-key.pem
│   ├── broker-ca.pem
│   └── italmetal
│       ├── ca-key.pem
│       ├── ca.pem
│       ├── italmetal__supplier.env
│       ├── italmetal__supplier-key.pem
│       └── italmetal__supplier.pem
├── CLAUDE.md
├── commands.md
├── cript_messages.md
├── demo
│   ├── 04_demo_broker.md
│   ├── 04_demo_buyer.md
│   ├── 04_demo_certs.md
│   ├── 04_demo_manufacturer.md
│   ├── 05_demo_broker.md
│   ├── 05_demo_buyer.md
│   ├── 05_demo_certs.md
│   ├── 05_demo_manufacturer.md
│   ├── 06_demo_bootstrap.md
│   ├── 06_demo_broker.md
│   ├── 06_demo_buyer.md
│   ├── 06_demo_certs.md
│   ├── 06_demo_manufacturer.md
│   ├── demo-bootstrap-01.md
│   ├── demo-bootstrap-02.md
│   ├── demo-broker-01.md
│   ├── demo-broker-02.md
│   ├── demo-broker-03.md
│   ├── demo-buyer-01.md
│   ├── demo-buyer-02.md
│   ├── demo-buyer-03.md
│   ├── demo-kyc-output.md
│   ├── demo-manufacturer-01.md
│   ├── demo-manufacturer-02.md
│   └── demo-manufacturer-03.md
├── drafts
│   ├── draft-hartman-credential-broker-4-agents-00.md
│   ├── draft-klrc-aiagent-auth-01.md
│   └── wimse.md
├── files
│   └── claude-project-instructions.md
├── files.zip
├── flusso_policy.md
├── generate_certs.py
├── join_agent.py
├── join.py
├── mcp_proxy.md
├── miglioramenti
│   ├── main.md
│   └── x509_verifier.md
├── payments.md
├── policy.py
├── progress.md
├── __pycache__
│   └── bootstrap.cpython-311.pyc
├── pytest.ini
├── README.md
├── repository
│   ├── ARCHITECTURE.md
│   ├── LICENSE
│   └── README.md
├── requirements.txt
├── reset.sh
├── revoke.py
├── roadmap.md
├── roadmapV2.md
├── run.sh
├── security_context.md
├── shell.nix
├── showcase
│   ├── 07-demo-bootstrap.md
│   ├── 07-demo-broker.md
│   ├── 07-demo-buyer.md
│   ├── 07-demo-manufacturer.md
│   ├── 08-demo-brooker.md
│   ├── 08-demo-certs.md
│   ├── 08-demo-join.md
│   ├── 2026-03-28 17-35-55.mp4
│   ├── 2026-03-28-17-35-55_z38BtSSX.mp4
│   ├── PITCH_DECK.md
│   └── PRESENTATION.md
├── showcase.zip
├── tests
│   ├── cert_factory.py
│   ├── conftest.py
│   ├── __init__.py
│   ├── __pycache__
│   │   ├── cert_factory.cpython-311.pyc
│   │   ├── conftest.cpython-311-pytest-8.3.4.pyc
│   │   ├── __init__.cpython-311.pyc
│   │   ├── test_auth.cpython-311-pytest-8.3.4.pyc
│   │   ├── test_binding.cpython-311-pytest-8.3.4.pyc
│   │   ├── test_broker.cpython-311-pytest-8.3.4.pyc
│   │   ├── test_discovery.cpython-311-pytest-8.3.4.pyc
│   │   ├── test_e2e.cpython-311-pytest-8.3.4.pyc
│   │   ├── test_injection.cpython-311-pytest-8.3.4.pyc
│   │   ├── test_message_signature.cpython-311-pytest-8.3.4.pyc
│   │   ├── test_onboarding.cpython-311-pytest-8.3.4.pyc
│   │   ├── test_persistence.cpython-311-pytest-8.3.4.pyc
│   │   ├── test_policy.cpython-311-pytest-8.3.4.pyc
│   │   ├── test_postgres_integration.cpython-311-pytest-8.3.4.pyc
│   │   ├── test_rate_limit.cpython-311-pytest-8.3.4.pyc
│   │   ├── test_revocation.cpython-311-pytest-8.3.4.pyc
│   │   ├── test_role_policy.cpython-311-pytest-8.3.4.pyc
│   │   ├── test_spiffe.cpython-311-pytest-8.3.4.pyc
│   │   └── test_ws.cpython-311-pytest-8.3.4.pyc
│   ├── test_auth.py
│   ├── test_binding.py
│   ├── test_broker.py
│   ├── test_discovery.py
│   ├── test_e2e.py
│   ├── test_injection.py
│   ├── test_message_signature.py
│   ├── test_onboarding.py
│   ├── test_persistence.py
│   ├── test_policy.py
│   ├── test_postgres_integration.py
│   ├── test_rate_limit.py
│   ├── test_revocation.py
│   ├── test_role_policy.py
│   ├── test_spiffe.py
│   └── test_ws.py
├── traceability_ledger.md
├── transaction_token.md
└── trust_federation.md
