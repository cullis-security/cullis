# Changelog

All notable changes to `@agent-trust/sdk` (the Cullis TypeScript SDK)
are documented here. The SDK follows [Semantic
Versioning](https://semver.org/spec/v2.0.0.html) once a stable `1.0.0`
is cut; pre-1.0 releases may break the public API between minor
versions and document each break here.

## 0.2.0-beta.0 — 2026-05-20

Audit-driven polish pass. Closes F-B-304 (version skew vs Python SDK)
and F-B-307 (`verifyTls` API was a lie).

### Changed

- **`verifyTls` removed from `BrokerClientOptions`.** The option used
  to be accepted at type level and either silently ignored (`true`)
  or rejected at construction time (`false`). Node's native fetch
  cannot disable TLS verification per-call, and the process-wide
  escape hatch `NODE_TLS_REJECT_UNAUTHORIZED=0` is unsafe. The new
  surface fails clearly: no option, no hidden behaviour. For brokers
  with a private or self-signed CA, point Node at the CA PEM via
  `NODE_EXTRA_CA_CERTS=/path/to/ca.pem` (see README "Self-signed /
  private CA"). [F-B-307]
- Package version bumped from `0.1.0` to `0.2.0-beta.0` to (a) flag
  the parity gap with `cullis_sdk` 0.1.3 surfaced in
  [F-B-301](../imp/audits/2026-05-20/findings/track-b/F-B-301.md) and
  (b) match the wider Cullis 0.5 wire surface this SDK targets.
  [F-B-304]

### Migration

If you were constructing the client with `verifyTls: true`, just drop
the option. If you were passing `verifyTls: false` (which threw at
runtime anyway), switch to `NODE_EXTRA_CA_CERTS` and remove the
option:

```diff
- const client = new BrokerClient({ baseUrl, verifyTls: false });
+ // export NODE_EXTRA_CA_CERTS=/path/to/cullis-ca.pem
+ const client = new BrokerClient({ baseUrl });
```

## 0.1.0 — 2025-12 (unreleased to npm)

Initial 2025-Q4 session-based wire surface:

- x509 + DPoP (RFC 9449) login.
- Session lifecycle (open, accept, send, poll, close, list).
- E2E encryption (AES-256-GCM + RSA-OAEP-SHA256) with double signature
  (RSA-PSS-SHA256 inner + outer).
- Agent discovery (capability-filtered).
- RFQ flow (request, list responses, accept).
- Transaction tokens.
- Automatic DPoP nonce handling with single retry.

Not on npm; lived only in the source tree pending the parity work
tracked in F-B-301.
