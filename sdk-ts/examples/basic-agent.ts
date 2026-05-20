/**
 * Example: Basic buyer agent using the TypeScript SDK.
 *
 * STATUS: legacy session API. The flow demonstrated below
 * (login + openSession + send + poll + closeSession) mirrors the
 * Python SDK's deprecated `open_session()` / `send()` surface, which
 * emits `DeprecationWarning` and will be removed in `cullis-sdk` v0.5
 * (~2026-08-15). The canonical Cullis A2A flow is one-shot messaging
 * (ADR-008: `send_oneshot` + `receive_oneshot` + ACK), which the TS
 * SDK does not yet expose (tracked as F-B-301 in the audit /
 * Roadmap section of sdk-ts/README.md). This example documents what
 * the TS SDK can actually do today; new TypeScript integrations that
 * can wait for parity should prefer `cullis_sdk` (Python) and its
 * `send_oneshot()` flow.
 *
 * Demonstrates:
 *  1. Authenticating with the broker
 *  2. Discovering supplier agents
 *  3. Opening a session
 *  4. Sending an E2E encrypted message
 *  5. Polling for the response
 *
 * Usage:
 *   BROKER_URL=https://localhost:8443 \
 *   AGENT_ID=acme::buyer-agent \
 *   ORG_ID=acme \
 *   CERT_PATH=./certs/buyer.crt \
 *   KEY_PATH=./certs/buyer.key \
 *     npx tsx examples/basic-agent.ts
 */
import { BrokerClient } from "../src/index.js";

async function main(): Promise<void> {
  const brokerUrl = process.env.BROKER_URL ?? "https://localhost:8443";
  const agentId = process.env.AGENT_ID ?? "acme::buyer-agent";
  const orgId = process.env.ORG_ID ?? "acme";
  const certPath = process.env.CERT_PATH ?? "./certs/buyer.crt";
  const keyPath = process.env.KEY_PATH ?? "./certs/buyer.key";

  // 1. Create client and authenticate
  const client = new BrokerClient({
    baseUrl: brokerUrl,
    verifyTls: process.env.VERIFY_TLS !== "false",
  });

  console.log(`[${agentId}] Logging in to ${brokerUrl}...`);
  await client.login(agentId, orgId, certPath, keyPath);
  console.log(`[${agentId}] Authenticated successfully.`);

  // 2. Discover supplier agents with the capabilities we need
  const capabilities = ["order.read", "order.write"];
  console.log(`[${agentId}] Searching for agents with capabilities: ${capabilities.join(", ")}...`);
  const agents = await client.discover(capabilities);

  if (agents.length === 0) {
    console.log(`[${agentId}] No agents found with required capabilities.`);
    return;
  }

  const target = agents[0];
  console.log(
    `[${agentId}] Found ${agents.length} agent(s). Connecting to ${target.agent_id} (${target.display_name})...`,
  );

  // 3. Open a session
  const sessionId = await client.openSession(
    target.agent_id,
    target.org_id,
    capabilities,
  );
  console.log(`[${agentId}] Session created: ${sessionId}`);

  // 4. Wait for session to be accepted
  console.log(`[${agentId}] Waiting for session acceptance...`);
  let accepted = false;
  for (let i = 0; i < 30; i++) {
    const sessions = await client.listSessions();
    const session = sessions.find((s) => s.session_id === sessionId);
    if (session?.status === "active") {
      accepted = true;
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }

  if (!accepted) {
    console.log(`[${agentId}] Timeout waiting for session acceptance.`);
    return;
  }

  console.log(`[${agentId}] Session active. Sending order request...`);

  // 5. Send an E2E encrypted message
  await client.send(sessionId, agentId, {
    type: "order_request",
    text: "I need a quote for 1000 zinc-plated M8 bolts, grade 8.8.",
    order_id: "ORD-2026-001",
  }, target.agent_id);

  console.log(`[${agentId}] Message sent. Polling for response...`);

  // 6. Poll for response
  let lastSeq = -1;
  for (let i = 0; i < 30; i++) {
    const messages = await client.poll(sessionId, lastSeq);
    for (const msg of messages) {
      if (msg.sender_agent_id !== agentId) {
        console.log(`[${agentId}] Received from ${msg.sender_agent_id}:`);
        console.log(`  <- ${(msg.payload as Record<string, string>).text ?? JSON.stringify(msg.payload)}`);
      }
      lastSeq = Math.max(lastSeq, msg.seq);
    }
    if (messages.some((m) => m.sender_agent_id !== agentId)) {
      break; // Got a response
    }
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }

  // 7. Close session
  await client.closeSession(sessionId);
  console.log(`[${agentId}] Session closed. Done.`);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
