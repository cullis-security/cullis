/**
 * End-to-end encryption and message signing for inter-agent messages.
 *
 * Encryption: AES-256-GCM (data)
 *   + RSA-OAEP-SHA256 (key wrapping, RSA recipients)
 *   + ECDH ephemeral + HKDF-SHA256 + AES-KW (key wrapping, EC recipients)
 * Signing:    RSA-PSS-SHA256 (RSA keys) or ECDSA-SHA256 (EC keys)
 *
 * This mirrors app/e2e_crypto.py and app/auth/message_signer.py exactly,
 * so that a TypeScript agent can interoperate with Python agents.
 */
import {
  createSign,
  createVerify,
  publicEncrypt,
  privateDecrypt,
  randomBytes,
  createCipheriv,
  createDecipheriv,
  createPublicKey,
  createPrivateKey,
  generateKeyPairSync,
  diffieHellman,
  hkdfSync,
  constants,
  X509Certificate,
  type KeyObject,
} from "node:crypto";
import type { CipherBlob } from "./types.js";
import { base64url, base64urlDecode, canonicalJson } from "./utils.js";

/**
 * H7 audit: parse a PEM string strictly as an X.509 certificate.
 * Bare SPKI public keys are rejected — the cert subject is what binds
 * the verifying key to ``senderAgentId``, and a bare SPKI carries no
 * identity. Returns ``null`` on parse failure or if the input is not a
 * CERTIFICATE PEM.
 */
function loadCertStrict(certPem: string): X509Certificate | null {
  if (!certPem || !certPem.includes("-----BEGIN CERTIFICATE-----")) {
    return null;
  }
  try {
    return new X509Certificate(certPem);
  } catch {
    return null;
  }
}

/**
 * H7 audit: bind the cert to ``expectedAgentId``. Mirrors the Python
 * ``_cert_trust.cert_binds_agent_id`` rule:
 *   - cert with CN: CN must equal the full ``{org}::{name}`` agent_id
 *   - cert with no CN, SPIFFE URI SAN: path tail must equal the
 *     short name (after the ``::`` split)
 */
function certBindsAgentId(cert: X509Certificate, expectedAgentId: string): boolean {
  if (!expectedAgentId) {
    return false;
  }
  // ``X509Certificate.subject`` is a multi-line string of the form
  // ``CN=acme::alice\nO=acme``. Walk it for a CN line.
  const subject = cert.subject ?? "";
  for (const line of subject.split("\n")) {
    const match = /^\s*CN=(.+?)\s*$/.exec(line);
    if (match) {
      return match[1] === expectedAgentId;
    }
  }
  // SPIFFE SAN fallback. ``subjectAltName`` is the comma-separated
  // OpenSSL-style string, e.g. ``URI:spiffe://td/org/agent``.
  const san = cert.subjectAltName ?? "";
  const expectedTail = expectedAgentId.includes("::")
    ? expectedAgentId.split("::").slice(-1)[0]
    : expectedAgentId;
  for (const entry of san.split(",")) {
    const trimmed = entry.trim();
    if (!trimmed.startsWith("URI:spiffe://")) continue;
    const uri = trimmed.slice("URI:".length);
    const tail = uri.split("/").pop() ?? "";
    if (tail === expectedTail) {
      return true;
    }
  }
  return false;
}

const HKDF_INFO = Buffer.from("cullis-e2e-v2-aeskw", "utf-8");
const HKDF_SALT = Buffer.alloc(0);
// RFC 3394 default IV for AES Key Wrap.
const AES_KW_DEFAULT_IV = Buffer.from("A6A6A6A6A6A6A6A6", "hex");

// ── Message Signing (RSA-PSS-SHA256) ──────────────────────────────

/**
 * Build the canonical byte string that gets signed.
 * Must match Python's _canonical() in app/auth/message_signer.py.
 */
function buildCanonical(
  sessionId: string,
  senderAgentId: string,
  nonce: string,
  timestamp: number,
  payload: Record<string, unknown>,
  clientSeq?: number | null,
): Buffer {
  const payloadStr = canonicalJson(payload);
  let canonical: string;
  if (clientSeq !== undefined && clientSeq !== null) {
    canonical = `${sessionId}|${senderAgentId}|${nonce}|${timestamp}|${clientSeq}|${payloadStr}`;
  } else {
    canonical = `${sessionId}|${senderAgentId}|${nonce}|${timestamp}|${payloadStr}`;
  }
  return Buffer.from(canonical, "utf-8");
}

/**
 * Sign a message. The algorithm is dispatched from the private key type:
 *   RSA  → RSA-PSS-SHA256, MGF1-SHA256, max salt length
 *   EC   → ECDSA-SHA256 (DER-encoded signature, as produced by Node.js
 *          and consumed by Python's cryptography library)
 * Returns the signature as a URL-safe base64 string (no padding).
 */
export function signMessage(
  privateKeyPem: string,
  sessionId: string,
  senderAgentId: string,
  nonce: string,
  timestamp: number,
  payload: Record<string, unknown>,
  clientSeq?: number | null,
): string {
  const canonical = buildCanonical(
    sessionId, senderAgentId, nonce, timestamp, payload, clientSeq,
  );
  const keyObj = createPrivateKey(privateKeyPem);
  const signer = createSign("SHA256");
  signer.update(canonical);

  let signature: Buffer;
  if (keyObj.asymmetricKeyType === "rsa") {
    signature = signer.sign({
      key: keyObj,
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: constants.RSA_PSS_SALTLEN_MAX_SIGN,
    });
  } else if (keyObj.asymmetricKeyType === "ec") {
    signature = signer.sign(keyObj);
  } else {
    throw new Error(
      `Unsupported signing key type: ${keyObj.asymmetricKeyType}`,
    );
  }
  return base64url(signature);
}

/**
 * Verify a message signature. Algorithm is dispatched from the public key
 * type (RSA-PSS-SHA256 or ECDSA-SHA256). Returns true, throws on failure.
 *
 * H7 audit fix: ``certPem`` MUST be a full X.509 certificate PEM. Bare
 * SPKI public keys are rejected, and the cert subject must identify
 * ``senderAgentId``. See the Python ``_cert_trust`` module for the
 * full rationale.
 */
export function verifyMessageSignature(
  certPem: string,
  signatureB64: string,
  sessionId: string,
  senderAgentId: string,
  nonce: string,
  timestamp: number,
  payload: Record<string, unknown>,
  clientSeq?: number | null,
): boolean {
  const cert = loadCertStrict(certPem);
  if (cert === null) {
    throw new Error(
      "Message signature verification failed: expected an X.509 " +
        "CERTIFICATE PEM (bare SPKI public keys are no longer accepted)",
    );
  }
  if (!certBindsAgentId(cert, senderAgentId)) {
    throw new Error(
      "Message signature verification failed: cert subject does not " +
        `bind sender_agent_id ${senderAgentId}`,
    );
  }
  const canonical = buildCanonical(
    sessionId, senderAgentId, nonce, timestamp, payload, clientSeq,
  );
  const sig = base64urlDecode(signatureB64);
  const keyObj = cert.publicKey;
  const verifier = createVerify("SHA256");
  verifier.update(canonical);

  let valid: boolean;
  if (keyObj.asymmetricKeyType === "rsa") {
    valid = verifier.verify(
      {
        key: keyObj,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: constants.RSA_PSS_SALTLEN_MAX_SIGN,
      },
      sig,
    );
  } else if (keyObj.asymmetricKeyType === "ec") {
    valid = verifier.verify(keyObj, sig);
  } else {
    throw new Error(
      `Unsupported verification key type: ${keyObj.asymmetricKeyType}`,
    );
  }

  if (!valid) {
    throw new Error("Message signature verification failed");
  }
  return true;
}

// ── E2E Encryption (AES-256-GCM + RSA-OAEP or ECDH+HKDF+AES-KW) ──

function wrapAesKeyRsa(
  recipientPubKey: KeyObject,
  aesKey: Buffer,
): { encrypted_key: string } {
  const encryptedKey = publicEncrypt(
    {
      key: recipientPubKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    aesKey,
  );
  return { encrypted_key: base64url(encryptedKey) };
}

function wrapAesKeyEc(
  recipientPubKey: KeyObject,
  aesKey: Buffer,
): { encrypted_key: string; ephemeral_pubkey: string } {
  const details = recipientPubKey.asymmetricKeyDetails;
  const namedCurve = details?.namedCurve;
  if (!namedCurve) {
    throw new Error("EC recipient key missing namedCurve");
  }
  const ephemeral = generateKeyPairSync("ec", { namedCurve });
  const sharedSecret = diffieHellman({
    privateKey: ephemeral.privateKey,
    publicKey: recipientPubKey,
  });
  const kek = Buffer.from(
    hkdfSync("sha256", sharedSecret, HKDF_SALT, HKDF_INFO, 32),
  );
  const wrap = createCipheriv("aes256-wrap", kek, AES_KW_DEFAULT_IV);
  const encryptedKey = Buffer.concat([wrap.update(aesKey), wrap.final()]);
  const ephemeralPubPem = ephemeral.publicKey
    .export({ type: "spki", format: "pem" })
    .toString();
  return {
    encrypted_key: base64url(encryptedKey),
    ephemeral_pubkey: base64url(Buffer.from(ephemeralPubPem, "utf-8")),
  };
}

function unwrapAesKeyRsa(
  recipientPrivKey: KeyObject,
  blob: CipherBlob,
): Buffer {
  const encryptedKey = base64urlDecode(blob.encrypted_key);
  return privateDecrypt(
    {
      key: recipientPrivKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    encryptedKey,
  );
}

function unwrapAesKeyEc(
  recipientPrivKey: KeyObject,
  blob: CipherBlob,
): Buffer {
  if (!blob.ephemeral_pubkey) {
    throw new Error("EC recipient requires ephemeral_pubkey in cipher blob");
  }
  const ephemeralPubPem = base64urlDecode(blob.ephemeral_pubkey).toString(
    "utf-8",
  );
  const ephemeralPub = createPublicKey(ephemeralPubPem);
  const sharedSecret = diffieHellman({
    privateKey: recipientPrivKey,
    publicKey: ephemeralPub,
  });
  const kek = Buffer.from(
    hkdfSync("sha256", sharedSecret, HKDF_SALT, HKDF_INFO, 32),
  );
  const encryptedKey = base64urlDecode(blob.encrypted_key);
  const unwrap = createDecipheriv("aes256-wrap", kek, AES_KW_DEFAULT_IV);
  return Buffer.concat([unwrap.update(encryptedKey), unwrap.final()]);
}


/**
 * Encrypt a payload for a specific recipient agent.
 *
 * Schema: AES-256-GCM encrypts {payload, inner_signature} as JSON.
 * The AES key is wrapped with the recipient's public key:
 *   - RSA keys: RSA-OAEP-SHA256
 *   - EC keys:  ephemeral ECDH + HKDF-SHA256 (info="cullis-e2e-v2-aeskw") + AES-KW (RFC 3394)
 * AAD binds the ciphertext to the session context.
 */
export function encryptForAgent(
  payload: Record<string, unknown>,
  recipientPublicKeyPem: string,
  sessionId: string,
  senderAgentId: string,
  innerSignature: string,
  clientSeq?: number | null,
): CipherBlob {
  const innerEnvelope = canonicalJson({
    inner_signature: innerSignature,
    payload,
  });
  const plaintext = Buffer.from(innerEnvelope, "utf-8");

  const aesKey = randomBytes(32);
  const iv = randomBytes(12);

  let aad: Buffer;
  if (clientSeq !== undefined && clientSeq !== null) {
    aad = Buffer.from(`${sessionId}|${senderAgentId}|${clientSeq}`, "utf-8");
  } else {
    aad = Buffer.from(`${sessionId}|${senderAgentId}`, "utf-8");
  }

  const cipher = createCipheriv("aes-256-gcm", aesKey, iv);
  cipher.setAAD(aad);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const ciphertextWithTag = Buffer.concat([encrypted, authTag]);

  const recipientPubKey = createPublicKey(recipientPublicKeyPem);
  let keyWrap: { encrypted_key: string; ephemeral_pubkey?: string };
  if (recipientPubKey.asymmetricKeyType === "rsa") {
    keyWrap = wrapAesKeyRsa(recipientPubKey, aesKey);
  } else if (recipientPubKey.asymmetricKeyType === "ec") {
    keyWrap = wrapAesKeyEc(recipientPubKey, aesKey);
  } else {
    throw new Error(
      `Unsupported recipient key type: ${recipientPubKey.asymmetricKeyType}`,
    );
  }

  return {
    ciphertext: base64url(ciphertextWithTag),
    iv: base64url(iv),
    ...keyWrap,
  };
}

/**
 * Decrypt an E2E encrypted message.
 * Supports both RSA-OAEP and ECDH+HKDF key unwrapping.
 *
 * @returns [plaintextPayload, innerSignature]
 */
export function decryptFromAgent(
  encryptedMessage: CipherBlob,
  privateKeyPem: string,
  sessionId: string,
  senderAgentId: string,
  clientSeq?: number | null,
): [Record<string, unknown>, string] {
  const recipientPrivKey = createPrivateKey(privateKeyPem);
  let aesKey: Buffer;
  if (recipientPrivKey.asymmetricKeyType === "rsa") {
    aesKey = unwrapAesKeyRsa(recipientPrivKey, encryptedMessage);
  } else if (recipientPrivKey.asymmetricKeyType === "ec") {
    aesKey = unwrapAesKeyEc(recipientPrivKey, encryptedMessage);
  } else {
    throw new Error(
      `Unsupported recipient key type: ${recipientPrivKey.asymmetricKeyType}`,
    );
  }

  const ivBuf = base64urlDecode(encryptedMessage.iv);
  const ciphertextWithTag = base64urlDecode(encryptedMessage.ciphertext);

  // Split: ciphertext is everything except last 16 bytes (GCM tag)
  const tagStart = ciphertextWithTag.length - 16;
  const ciphertext = ciphertextWithTag.subarray(0, tagStart);
  const authTag = ciphertextWithTag.subarray(tagStart);

  // Build AAD
  let aad: Buffer;
  if (clientSeq !== undefined && clientSeq !== null) {
    aad = Buffer.from(`${sessionId}|${senderAgentId}|${clientSeq}`, "utf-8");
  } else {
    aad = Buffer.from(`${sessionId}|${senderAgentId}`, "utf-8");
  }

  // AES-256-GCM decrypt
  const decipher = createDecipheriv("aes-256-gcm", aesKey, ivBuf);
  decipher.setAAD(aad);
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  const data = JSON.parse(plaintext.toString("utf-8")) as {
    payload: Record<string, unknown>;
    inner_signature: string;
  };

  return [data.payload, data.inner_signature];
}
