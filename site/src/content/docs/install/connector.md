---
title: "Install the Connector"
description: "Download the Cullis Connector desktop release, install it on macOS, Linux, or Windows, and complete your first enrollment against your organization's Mastio."
category: "Install"
order: 10
updated: "2026-05-03"
---

# Install the Connector

**Who this is for**: an end-user developer who wants to expose MCP resources behind their Cullis identity — Claude Desktop, Cursor, Cline, Claude Code CLI, or any MCP client. Your org admin has already deployed a Mastio and can approve your enrollment.

## Prerequisites

- macOS 12+, Windows 10+, or Linux with `glibc ≥ 2.31`
- 100 MB disk, 200 MB RAM
- Your Mastio URL (ask your admin — typically `https://cullis.acme.local` or `https://localhost:9443` during first-time setup; ADR-014 made the Mastio TLS-only with a self-signed Org-CA leaf — pass `--insecure-tls` for the dev case)
- A reachable admin who can approve your enrollment in the Mastio dashboard

## 1. Download

Pick one of three install channels. All produce the same `cullis-connector` binary; choose based on how your laptop is managed.

### A. Desktop installer (zip from GitHub Releases)

The official release bundles a single executable per platform — no Python install, no network libraries to match. The links below always resolve to the latest release.

| Platform | File | Unpack |
|---|---|---|
| macOS (Apple Silicon) | [`cullis-connector-macos.zip`](https://github.com/cullis-security/cullis/releases/latest/download/cullis-connector-macos.zip) | `unzip cullis-connector-macos.zip && chmod +x cullis-connector-macos-arm64` |
| Linux x86_64 | [`cullis-connector-linux.zip`](https://github.com/cullis-security/cullis/releases/latest/download/cullis-connector-linux.zip) | `unzip cullis-connector-linux.zip && chmod +x cullis-connector-linux-x86_64` |
| Windows x86_64 | [`cullis-connector-windows.zip`](https://github.com/cullis-security/cullis/releases/latest/download/cullis-connector-windows.zip) | Right-click → Extract All. Then place `cullis-connector-windows-x86_64.exe` on your `PATH`. |

Each zip ships the platform-specific binary plus an `install.sh` / `install.command` / `install.bat` helper that puts the binary on `PATH` for you. If you prefer to do it by hand:

```bash
# Linux example — adjust filename for your platform
sudo mv cullis-connector-linux-x86_64 /usr/local/bin/cullis-connector
cullis-connector --version
# cullis-connector 0.3.6
```

> macOS Intel and Linux on ARM are not currently published as standalone binaries. Use **option B (`pip install`)** on those platforms.

### B. `pip install` (Python 3.10+)

```bash
pip install cullis-connector
cullis-connector --version
```

Useful if you want the `[dashboard,desktop]` extras for the native OS webview:

```bash
pip install 'cullis-connector[dashboard,desktop]'
```

### C. Homebrew (macOS, Linux) — *coming soon*

A `cullis-security/homebrew-tap` is on the roadmap but not yet published. In the meantime use option **A** (zip) or **B** (`pip install`) on macOS — both produce the same `cullis-connector` binary.

## 2. First enrollment

You only enroll **once per machine**. The identity that lands at the end of this step is shared by every MCP client you'll wire up later — Cline, Cursor, Zed, Windsurf, Claude Desktop. Pick the path that fits you better; both produce the same artefacts under `~/.cullis/identity/`.

### Option A — Dashboard wizard (recommended)

The friendliest path on a fresh laptop. Start the dashboard and let the browser walk you through it:

```bash
cullis-connector dashboard
# Connector dashboard running at http://127.0.0.1:7777
```

Open `http://127.0.0.1:7777`. If no identity exists yet, you land on a 3-step wizard:

1. **Connect** — paste your Mastio URL (e.g. `https://cullis.acme.local:9443`) and optionally pin the CA fingerprint your admin gave you over a separate channel.
2. **Approve** — the dashboard prints an approval URL for your admin. The page auto-refreshes while polling; no need to keep a terminal open.
3. **Online** — once the admin approves, the dashboard switches to the Connected view with your agent id, org, and the IDE cards (see step 4).

### Option B — CLI

For headless setups (CI runners, remote servers, no display):

```bash
cullis-connector enroll \
    --site-url https://cullis.acme.local \
    --requester-name "Alice Example" \
    --requester-email "alice@acme.example" \
    --reason "New laptop, replacing the old MBP"
```

What happens under the hood (same for both options):

1. The Connector generates a fresh EC P-256 keypair under `~/.cullis/identity/`. The private key never leaves your machine.
2. It POSTs the public key to `POST /v1/enrollments` on the Mastio. The Mastio replies with an enrollment session id and a challenge nonce (see [Connector device-code enrollment](../enroll/connector-device-code) for the challenge-response flow introduced in connector-v0.3.0).
3. The CLI / dashboard prints an approval URL — share it with your admin.
4. The Connector polls every 3 seconds until the admin approves in the Mastio dashboard (`/proxy/enrollments`).
5. On approval, the Connector completes a challenge-response handshake proving it still holds the private key, then writes `identity.pem`, `identity-key.pem`, and `agent.json` under `~/.cullis/identity/`.

Expected CLI output (elided):

```
[cullis-connector] Generated fresh P-256 keypair (~/.cullis/identity/identity-key.pem)
[cullis-connector] Enrollment session: 01JXF2...SRV
[cullis-connector] Share this URL with your admin:
    https://cullis.acme.local/proxy/enrollments/01JXF2...SRV
[cullis-connector] Waiting for admin approval... (poll every 3s)
[cullis-connector] ✓ Approved by alice-admin@acme.example
[cullis-connector] ✓ Challenge-response completed
[cullis-connector] ✓ Identity persisted to ~/.cullis/identity/
```

Time to approval depends on your admin; the default session TTL is 1 hour.

## 3. Open the dashboard

If you used the dashboard wizard in step 2, you're already on it. To re-open later:

```bash
cullis-connector dashboard
# Connector dashboard running at http://127.0.0.1:7777
```

Open `http://127.0.0.1:7777` in your browser. The Connected view shows your enrollment details (agent id, org, Mastio URL), MCP resources you're bound to, and a card per detected MCP client.

For a tray icon + native webview (no browser tab), use the optional desktop shell:

```bash
pip install 'cullis-connector[dashboard,desktop]'
cullis-connector desktop
```

Platform notes:

- **macOS / Windows 10+**: nothing extra to install.
- **Linux**: install `gtk3` + `webkit2gtk` from your distro (`apt install libgtk-3-0 libwebkit2gtk-4.1-0`).
- **NixOS**: the `desktop` shell currently fails on NixOS because `pystray` and `pywebview` can't bind to the system tray under the Nix store layout. Use `cullis-connector dashboard` (browser-based) instead.

## 4. How identity binds to your IDEs

Three things to internalise before you click around in step 5; none of them are optional reading.

**One identity per machine, shared by every IDE.** The enrolment in step 2 creates *one* keypair + cert under `~/.cullis/identity/`. Every MCP client you wire up — Cline, Cursor, Zed, Windsurf, Claude Desktop, Claude Code CLI — invokes the same `cullis-connector serve` binary, which holds that single identity. From the network's point of view all of them are the same agent. There is no per-IDE enrolment.

> If you genuinely need separate identities on the same laptop (e.g. a personal bot and a work bot), the Connector supports **profiles** — see [Multi-profile setup](https://github.com/cullis-security/cullis/blob/main/cullis_connector/README.md#multiple-profiles-on-the-same-machine). It is rarely what people want.

**The Connector is model-agnostic.** Cullis exposes its tools (`list_agents`, `open_session`, `send_message`, …) over MCP. The MCP protocol doesn't care which LLM your client is talking to. So if you switch Cline from Claude to Gemini to a local Ollama model, the Cullis tools keep working. The identity is yours, not the model's. This is the whole point: Cullis is the trust + audit layer, not the AI.

**Detected ≠ Configured.** The dashboard shows cards for every IDE it finds on disk:

- **Configured** — the MCP entry for `cullis` is already in that IDE's config file. Nothing to do.
- **Detected** — the IDE is installed but its config file doesn't mention Cullis yet. Click the card to write the entry.
- **Not detected** — the IDE isn't installed (or, for Cline specifically, the VS Code extension `saoudrizwan.claude-dev` hasn't been installed yet — `code --install-extension saoudrizwan.claude-dev` and restart VS Code).

The dashboard never writes to a client's config without an explicit click. Detection only tells you "I see this IDE installed", not "I patched it for you". If you launch a new IDE while the dashboard is open, refresh the page — detection re-runs on every page load.

## 5. Wire up your MCP client

In the dashboard's **Connected** view, click each IDE card you want to bind to Cullis. The Connector merges a `cullis` MCP entry into that IDE's config file (atomic write, backup of any pre-existing file goes to `~/.cullis/backups/`). **Restart the IDE** afterwards — most MCP clients only re-read their server list at startup.

For Claude Code CLI specifically, the dashboard shells out to:

```bash
claude mcp add cullis --scope user -- cullis-connector serve
```

If your MCP client isn't auto-detected (custom build, unusual install path), use the **Other MCP client** card on the same view: it copies the JSON snippet to your clipboard so you can paste it into the right config file by hand. The snippet is:

```json
{
  "mcpServers": {
    "cullis": {
      "command": "cullis-connector",
      "args": ["serve"]
    }
  }
}
```

Common file paths if you're patching by hand: `~/.config/Claude/claude_desktop_config.json` (Claude Desktop), `~/.cursor/mcp.json` (Cursor), `~/.codeium/windsurf/mcp_config.json` (Windsurf). Zed uses a different key — `context_servers`, not `mcpServers` — inside `~/.config/zed/settings.json`.

Once you restart the client, your Cullis tools (`list_agents`, `open_session`, `send_message`, etc.) should appear in its tool list.

## 6. Autostart on login (optional)

```bash
cullis-connector install-autostart
```

Registers a launch agent on macOS, a systemd user service on Linux, or a startup entry on Windows. The Connector tray icon appears at login and stays ready to serve MCP requests.

## Troubleshoot

**`Enrollment refused: htu mismatch`**
: Your Connector and the Mastio disagree on the Mastio's public URL. Ask your admin to confirm `MCP_PROXY_PROXY_PUBLIC_URL` in `proxy.env` matches the `--site-url` you passed.

**`Certificate verification failed`**
: The Mastio is serving a self-signed cert (development deploy). Either get a real TLS cert for the Mastio, or pass `--insecure-tls` — but **only** for `--dev` localhost demos. Never in production.

**Admin never sees the approval row**
: Check `/proxy/enrollments` on the Mastio with admin credentials. If the list is empty, the `POST /v1/enrollments` request never reached the Mastio — typical causes are a reverse-proxy dropping the `/v1/enrollments` path, or corporate network egress blocking the outbound call.

**Multiple profiles on the same laptop**
: Use `--profile north` / `--profile south` on every command. Each profile lives under `~/.cullis/profiles/<name>/` with its own identity. See the [Connector README](https://github.com/cullis-security/cullis/blob/main/cullis_connector/README.md#multiple-profiles-on-the-same-machine) for the full flow.

## Next

- [Connector device-code enrollment](../enroll/connector-device-code) — the challenge-response protocol under the hood
- [Sandbox walkthrough](../quickstart/sandbox-walkthrough) — try the whole flow against the local sandbox before you touch production
- [Getting started](../quickstart/getting-started) — decision tree if you're not sure the Connector is the right enrollment method for you
