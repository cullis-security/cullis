# `cullis-connector`

**The user-side binary for the Cullis federated agent-trust network.**

The Cullis Connector is a small MCP (Model Context Protocol) server that
runs on your workstation, inside your MCP client of choice (Claude Code,
Cursor, Claude Desktop, ToolHive, or any other MCP-speaking client), and
bridges that client into the Cullis network. It handles:

- **Enrollment** — one-time device-code flow that provisions your
  identity against the Cullis Site.
- **Session management** — opening, routing, and closing agent-to-agent
  sessions over the Cullis broker.
- **Discovery** — browsing agents and services reachable from your org.
- **Diagnostics** — local troubleshooting commands, exposed as MCP tools
  so the host LLM can run them with your approval.

The connector is one of three Cullis components:

| Component       | Runs where                   | Purpose                                    |
|-----------------|------------------------------|--------------------------------------------|
| Cullis Site     | Per-org control plane        | Admin UI, enrollment approvals, CA         |
| Cullis Broker   | Per-org data plane           | Routing, policy, audit                     |
| Cullis Connector| End-user workstation         | Binds the user's MCP client into the net   |

---

## Install

### PyPI (recommended)

```bash
pip install cullis-connector
cullis-connector --version
```

Python 3.10+ required. The package installs a single console script:
`cullis-connector`.

### Homebrew (macOS and Linux)

```bash
brew tap cullis-security/tap
brew install cullis-connector
```

### Docker

```bash
docker pull ghcr.io/cullis-security/cullis-connector:latest
docker run --rm ghcr.io/cullis-security/cullis-connector:latest --version
```

Persist the identity by mounting `~/.cullis`:

```bash
docker run --rm -it \
  -v "$HOME/.cullis:/home/cullis/.cullis" \
  ghcr.io/cullis-security/cullis-connector:latest \
  enroll --site-url https://cullis.acme.local \
    --requester-name "Alice" --requester-email "alice@acme.example"
```

### Standalone binary (GitHub Releases)

Each release on
<https://github.com/cullis-security/cullis/releases> ships pre-built
PyInstaller binaries for Linux amd64 and macOS. Download, `chmod +x`,
drop on your `$PATH`.

---

## Enroll

The first run needs a one-time enrollment against your org's Cullis
Site. Your admin receives an approval prompt; once they click approve,
the connector persists a client certificate and key under
`~/.cullis/identity/`.

```bash
cullis-connector enroll \
  --site-url https://cullis.acme.local \
  --requester-name "Alice Example" \
  --requester-email "alice@acme.example" \
  --reason "New laptop, replacing the old MBP"
```

The command prints a URL you can share with your admin and polls until
approval or timeout. See `cullis-connector enroll --help` for all flags.

---

## Wire up your MCP client

Every example below assumes you have already enrolled successfully.

### Claude Code

```bash
claude mcp add cullis cullis-connector \
  -- --site-url https://cullis.acme.local
```

Or append to `~/.claude/settings.json` manually:

```json
{
  "mcpServers": {
    "cullis": {
      "command": "cullis-connector",
      "args": ["--site-url", "https://cullis.acme.local"]
    }
  }
}
```

### Cursor

Add to `~/.cursor/mcp.json` (or the project-local `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "cullis": {
      "command": "cullis-connector",
      "args": ["--site-url", "https://cullis.acme.local"]
    }
  }
}
```

Cursor picks up the connector on next IDE restart.

### Claude Desktop

Edit `claude_desktop_config.json`:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "cullis": {
      "command": "cullis-connector",
      "args": ["--site-url", "https://cullis.acme.local"]
    }
  }
}
```

Restart Claude Desktop — the Cullis tools appear in the MCP menu.

### ToolHive

ToolHive pulls MCP servers from its registry. The Cullis Connector is
planned to land there once the Docker image is public:

```bash
# (future, once listed in the ToolHive registry)
thv run cullis-connector -- --site-url https://cullis.acme.local
```

Until the registry entry is accepted, you can run the containerised
connector manually:

```bash
thv run --docker ghcr.io/cullis-security/cullis-connector:latest \
  -- --site-url https://cullis.acme.local
```

(Submission of the connector to the ToolHive registry is tracked as a
separate rollout step.)

---

## Configuration precedence

1. CLI flags (`--site-url`, `--config-dir`, `--log-level`, ...)
2. Environment variables (`CULLIS_SITE_URL`, `CULLIS_CONFIG_DIR`, ...)
3. `~/.cullis/config.yaml`

Multi-org users can point each client at a distinct directory:

```bash
cullis-connector --config-dir ~/.cullis-orgA serve
cullis-connector --config-dir ~/.cullis-orgB serve
```

---

## Troubleshooting

- **`No identity found`** — run `cullis-connector enroll ...` first.
- **TLS failures against a dev Site** — the admin must share the org
  CA cert; import it into your trust store, or pass `--no-verify-tls`
  for local development *only*.
- **`cullis-connector` not on `$PATH`** after `pip install` — your pip
  user bin directory is probably missing; add `python -m site --user-base`
  + `/bin` to `$PATH`, or install in a venv.

---

## License

`cullis-connector` is distributed under the
[Functional Source License 1.1 with Apache 2.0 future grant](../LICENSE).
SDKs (`cullis_sdk`, `sdk-ts`) are permissive Apache 2.0 — see the
monorepo root `LICENSE` files for the full text.
