# Local demo acceptance

Run these checks against a freshly extracted Mastio bundle, after `local-demo.py
prepare` and `up`. Use a dedicated state directory, synthetic data, and an unused
loopback port. Host Python needs `httpx`; Docker access is required. Model weights
and images must be prepared before starting the isolated environment.

```bash
python test/local-demo/acceptance.py \
  --bundle /path/to/cullis-mastio-bundle \
  --state /path/to/fresh-demo-state \
  --evidence /path/to/new-evidence
```

The runner requires an empty agent identity directory. It checks verified host
HTTPS, enrollment approval, container topology and nginx privileges, 17 TCP
probes, DNS denial with a positive control, actual model inference, and identity
and model access after a restart. It approves only the enrollment request it
created. A successful run leaves the demo running; stop it with the bundle's
`local-demo.py --state /path/to/fresh-demo-state down`.

For DNS, timeout or explicit EPERM/EACCES on send or receive counts as a blocked
query only in the negative control. Any received datagram fails that control.
Unrelated socket errors propagate; the positive control still requires a reply.

The runner removes its labelled probe containers and the dedicated project's
one-off agent jobs on completion, failure, SIGINT, or SIGTERM. It preserves the
services and state for diagnosis. Do not run other agent jobs in the same project
during acceptance. SIGKILL cannot run cleanup handlers.

## Cancellation regression

Prepare and start a separate demo with an empty agent identity. This regression
interrupts acceptance while an agent is waiting for approval and a network probe
is active, checks exit 130 and the absence of test containers, then runs `down`
and checks that no containers or networks from the project remain.

```bash
python test/local-demo/cancellation.py \
  --bundle /path/to/cullis-mastio-bundle \
  --state /path/to/cancellation-state \
  --evidence /path/to/new-cancellation-evidence \
  --signal SIGTERM
```

Repeat with `SIGINT` and a new evidence directory after starting the same demo
again. The cancelled enrollment request remains pending; no identity is approved
or granted by this test.

Evidence directories are private: they include service logs and model responses.
Keep them outside tracked paths and never publish state, credentials, or keys.
These checks cover installation and connectivity, not model answer quality,
autonomous tool planning, or production readiness.
