// Inner signature verification on receive — L9-C1 regression test.
//
// Verifies that ``BrokerClient.decryptPayload()`` (the receive-side hook
// invoked by ``poll()``) refuses to surface a plaintext that fails the
// non-repudiation check. A compromised broker that swaps the ciphertext
// after key-unwrap MUST be rejected loudly; previously the inner signature
// returned by ``decryptFromAgent`` was discarded and forged plaintext
// would have been silently delivered to the application.
//
// Run via `npm test` (exits non-zero on any failure).
import assert from "node:assert/strict";
import { execSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync } from "node:crypto";

import { BrokerClient } from "../dist/client.js";
import { signMessage, encryptForAgent } from "../dist/crypto.js";

// ── Fixture helpers ────────────────────────────────────────────────

/**
 * Build a sender keypair + self-signed X.509 cert whose CN matches
 * ``agentId``. ``verifyMessageSignature`` rejects bare SPKI keys and
 * binds the cert subject to ``sender_agent_id``, so we need a real
 * cert with the correct CN.
 */
function makeSenderIdentity(agentId) {
  const tmp = mkdtempSync(join(tmpdir(), "cullis-sdk-test-"));
  const keyPath = join(tmp, "key.pem");
  const certPath = join(tmp, "cert.pem");

  // RSA key + self-signed cert via openssl. RSA chosen to exercise
  // the RSA-PSS-SHA256 signing path (the dominant production deployment
  // — ECDSA path is tested implicitly by the existing crypto helpers).
  execSync(
    `openssl req -x509 -newkey rsa:2048 -nodes ` +
      `-keyout ${keyPath} -out ${certPath} -days 1 ` +
      `-subj "/CN=${agentId}" 2>/dev/null`,
    { stdio: "pipe" },
  );
  return {
    keyPem: readFileSync(keyPath, "utf-8"),
    certPem: readFileSync(certPath, "utf-8"),
  };
}

/** Build a recipient RSA keypair as PEM. Recipients only need a key. */
function makeRecipientKeypair() {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  return {
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

/**
 * Construct a fully-formed encrypted ``InboxMessage`` as the broker
 * would deliver it on the wire — payload is a ``CipherBlob``, nonce
 * and timestamp on the envelope match what the sender signed.
 */
function buildEncryptedInbox({
  senderKeyPem,
  recipientPubPem,
  sessionId,
  senderAgentId,
  payload,
  clientSeq,
  // Defaults below let individual tests override (e.g. to fabricate a
  // signature mismatch by changing the nonce post-encrypt).
  nonce = "test-nonce-" + Math.random().toString(36).slice(2),
  timestamp = Math.floor(Date.now() / 1000),
}) {
  // Inner signature: signed over the plaintext payload.
  const innerSig = signMessage(
    senderKeyPem,
    sessionId,
    senderAgentId,
    nonce,
    timestamp,
    payload,
    clientSeq,
  );
  const cipherBlob = encryptForAgent(
    payload,
    recipientPubPem,
    sessionId,
    senderAgentId,
    innerSig,
    clientSeq,
  );
  return {
    seq: 0,
    sender_agent_id: senderAgentId,
    payload: cipherBlob,
    nonce,
    timestamp,
    signature: null,
    client_seq: clientSeq,
  };
}

/**
 * Build a ``BrokerClient`` instance plumbed for offline ``decryptPayload``
 * testing: signing key is set so decryption proceeds, and the pubkey
 * cache is pre-seeded with the sender's cert so no HTTP fetch happens.
 *
 * Reaches into private state through the ``any`` escape hatch; this
 * is a unit-test helper, not a real consumer pattern.
 */
function makeClientWithCachedSenderCert(recipientKeyPem, senderAgentId, senderCertPem) {
  const client = new BrokerClient({ baseUrl: "https://broker.test" });
  // Inject the recipient's signing key — required for ``decryptPayload``
  // to attempt decryption rather than no-op.
  client.signingKeyPem = recipientKeyPem;
  // Pre-seed the pubkey cache so ``getAgentPublicKey`` resolves without
  // hitting the (un-authenticated) HTTP path.
  client.pubkeyCache.set(senderAgentId, {
    pem: senderCertPem,
    fetchedAt: Date.now(),
  });
  return client;
}

// ── Tests ──────────────────────────────────────────────────────────

const sessionId = "test-session-" + Math.random().toString(36).slice(2);
const senderAgentId = "acme::alice";
const otherAgentId = "acme::eve";
const sender = makeSenderIdentity(senderAgentId);
const otherSender = makeSenderIdentity(otherAgentId);
const recipient = makeRecipientKeypair();

let failed = 0;

async function runCase(name, fn) {
  try {
    await fn();
    console.log(`  ok  ${name}`);
  } catch (err) {
    failed++;
    console.error(`  FAIL  ${name}: ${err.message}`);
  }
}

// Case 1 — happy path: a correctly-signed and -encrypted message
// round-trips and the plaintext is exposed to the caller.
await runCase("positive: valid inner sig — decryptPayload returns plaintext", async () => {
  const client = makeClientWithCachedSenderCert(
    recipient.privatePem, senderAgentId, sender.certPem,
  );
  const payload = { hello: "world", n: 42 };
  const inbox = buildEncryptedInbox({
    senderKeyPem: sender.keyPem,
    recipientPubPem: recipient.publicPem,
    sessionId,
    senderAgentId,
    payload,
    clientSeq: 0,
  });
  const out = await client.decryptPayload(inbox, sessionId);
  assert.deepEqual(out.payload, payload, "decrypted payload must match");
  assert.equal(out.sender_agent_id, senderAgentId);
});

// Case 2 — the broker (or anyone in the middle) re-encrypts a
// fabricated plaintext using the recipient's public key. AES-GCM
// alone would accept this; the inner signature must catch it.
await runCase("negative: fabricated plaintext (re-encrypted) — throws", async () => {
  const client = makeClientWithCachedSenderCert(
    recipient.privatePem, senderAgentId, sender.certPem,
  );
  const realPayload = { msg: "send $1 to charity" };
  const inbox = buildEncryptedInbox({
    senderKeyPem: sender.keyPem,
    recipientPubPem: recipient.publicPem,
    sessionId,
    senderAgentId,
    payload: realPayload,
    clientSeq: 1,
  });

  // Attacker re-encrypts a forged payload using the SAME inner signature
  // (which was computed over the legit payload, so it won't match the
  // forgery). If our verify step is missing, AES-GCM authenticates
  // happily because the AAD only binds session+sender+client_seq.
  const innerSigOverReal = signMessage(
    sender.keyPem, sessionId, senderAgentId, inbox.nonce, inbox.timestamp,
    realPayload, 1,
  );
  const forgedPayload = { msg: "send $1000000 to attacker" };
  inbox.payload = encryptForAgent(
    forgedPayload, recipient.publicPem, sessionId, senderAgentId,
    innerSigOverReal, 1,
  );

  await assert.rejects(
    () => client.decryptPayload(inbox, sessionId),
    /inner signature verification failed/i,
    "must reject forged plaintext re-encrypted by the broker",
  );
});

// Case 3 — wrong sender cert (e.g. registry returns Eve's cert when
// the message claims to be from Alice). The sig was produced with
// Alice's key but verify is attempted with Eve's key.
await runCase("negative: wrong sender cert — throws", async () => {
  const client = new BrokerClient({ baseUrl: "https://broker.test" });
  client.signingKeyPem = recipient.privatePem;
  // Cache returns OTHER agent's cert under Alice's id — the cert subject
  // doesn't bind ``acme::alice``, so ``verifyMessageSignature`` rejects.
  client.pubkeyCache.set(senderAgentId, {
    pem: otherSender.certPem,
    fetchedAt: Date.now(),
  });
  const inbox = buildEncryptedInbox({
    senderKeyPem: sender.keyPem,
    recipientPubPem: recipient.publicPem,
    sessionId,
    senderAgentId,
    payload: { ok: true },
    clientSeq: 2,
  });

  await assert.rejects(
    () => client.decryptPayload(inbox, sessionId),
    /inner signature verification failed/i,
    "must reject when registry returns the wrong cert for the sender",
  );
});

// Case 4 — the ciphertext envelope itself is replayed with a tampered
// nonce field (broker tries to make the recipient verify a different
// canonical). Inner sig was computed with the original nonce and won't
// validate against the tampered envelope.
await runCase("negative: tampered envelope nonce — throws", async () => {
  const client = makeClientWithCachedSenderCert(
    recipient.privatePem, senderAgentId, sender.certPem,
  );
  const inbox = buildEncryptedInbox({
    senderKeyPem: sender.keyPem,
    recipientPubPem: recipient.publicPem,
    sessionId,
    senderAgentId,
    payload: { v: 1 },
    clientSeq: 3,
  });
  // Broker rewrites the visible nonce. AAD does NOT include the nonce
  // (AAD = session|sender|client_seq), so AES-GCM still decrypts — only
  // the inner-signature check catches this.
  inbox.nonce = "broker-rewrote-this-nonce";

  await assert.rejects(
    () => client.decryptPayload(inbox, sessionId),
    /inner signature verification failed/i,
    "must reject envelope-level nonce tampering",
  );
});

// Case 5 — a single byte flip in the inner-signature blob makes
// verification fail even when everything else is consistent. Guards
// against the "AES-GCM said OK so I trust it" anti-pattern.
await runCase("negative: inner signature byte-flip — throws", async () => {
  const client = makeClientWithCachedSenderCert(
    recipient.privatePem, senderAgentId, sender.certPem,
  );
  const realPayload = { v: 2 };
  const inbox = buildEncryptedInbox({
    senderKeyPem: sender.keyPem,
    recipientPubPem: recipient.publicPem,
    sessionId,
    senderAgentId,
    payload: realPayload,
    clientSeq: 4,
  });

  // Re-encrypt with a corrupted inner signature. We flip a byte in
  // the middle of the original signature — RSA-PSS-SHA256 must reject.
  const goodSig = signMessage(
    sender.keyPem, sessionId, senderAgentId, inbox.nonce, inbox.timestamp,
    realPayload, 4,
  );
  // ``goodSig`` is base64url; decode, flip, re-encode — easier:
  // just overwrite a base64url char. Replace mid-string char with one
  // that's still in the base64url alphabet so decode itself succeeds.
  const mid = Math.floor(goodSig.length / 2);
  const orig = goodSig[mid];
  const flipped = orig === "A" ? "B" : "A";
  const corruptedSig = goodSig.slice(0, mid) + flipped + goodSig.slice(mid + 1);

  inbox.payload = encryptForAgent(
    realPayload, recipient.publicPem, sessionId, senderAgentId,
    corruptedSig, 4,
  );

  await assert.rejects(
    () => client.decryptPayload(inbox, sessionId),
    /inner signature verification failed/i,
    "must reject a single-byte flip in the inner signature",
  );
});

// ── Done ───────────────────────────────────────────────────────────

if (failed > 0) {
  console.error(`\n${failed} test(s) failed`);
  process.exit(1);
}
console.log(`\nall 5 inner-signature tests passed`);
