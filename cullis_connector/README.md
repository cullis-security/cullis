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

## Multiple profiles on the same machine

Need more than one identity on a single workstation — say a `north`
and a `south` agent for testing, or a personal profile alongside a
work one? Pass `--profile <name>` (or set `CULLIS_PROFILE`) and each
profile lives in its own directory under `~/.cullis/profiles/<name>/`
with a separate enrollment, config, and certificate.

```bash
# enroll two independent identities
cullis-connector enroll --profile north \
  --site-url https://cullis.acme.local \
  --requester-name "North Bot" --requester-email north@acme.example
cullis-connector enroll --profile south \
  --site-url https://cullis.acme.local \
  --requester-name "South Bot" --requester-email south@acme.example

# run them as two MCP stdio servers (different shell sessions or
# different IDE mcp.json entries)
cullis-connector serve --profile north
cullis-connector serve --profile south
```

Wiring both into the same MCP client is just two entries in its JSON:

```json
{
  "mcpServers": {
    "cullis-north": {"command": "cullis-connector", "args": ["serve", "--profile", "north"]},
    "cullis-south": {"command": "cullis-connector", "args": ["serve", "--profile", "south"]}
  }
}
```

Legacy installs using the flat `~/.cullis/identity/` layout keep
working untouched — we don't auto-migrate so existing keys aren't
moved without the operator's consent. To convert an in-place install
to a named profile, stop the connector and `mv ~/.cullis/identity
~/.cullis/profiles/default/identity` (same for any other state you
keep alongside).

Explicit `--config-dir /some/path` still wins over `--profile` for
operators who need to pin the directory elsewhere.

---

## Native desktop shell (no terminal)

```bash
pip install 'cullis-connector[dashboard,desktop]'
cullis-connector desktop
```

Launches a tray icon plus a native OS webview wrapping the local
dashboard — the process you'd usually see in a browser tab is now a
window on your taskbar. Closing the window hides it; quit from the
tray. The dashboard, enrollment flow, IDE autoconfig cards, and inbox
poller are identical to `cullis-connector dashboard`; only the shell
is native.

Platform prerequisites that `pip` cannot fetch:

- **macOS / Windows 10+**: nothing extra. The OS ships WebKit / WebView2.
- **Linux**: `gtk3` and `webkit2gtk` packages — present on mainstream
  distros out of the box, installable via the distro's package manager
  on minimal images (e.g. `apt install libgtk-3-0 libwebkit2gtk-4.1-0`).

Combine with `cullis-connector install-autostart` to have the tray
appear at login.

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

## Talking to other agents

Once enrolled, the connector exposes a small set of natural-language
MCP tools that your client (Claude Code, Cursor, …) calls on your
behalf. You don't memorise SPIFFE handles — the LLM picks them up
from the conversation.

**Find someone and start a thread:**
```
> contact mario
Active peer: Mario Rossi (chipfactory::mario).

> chat ciao, hai un attimo?
Sent to chipfactory::mario (correlation_id=…)
```

**Disambiguation when the name is shared:**
```
> contact mario
Found 3 matches for 'mario':
  #1  Mario Rossi   (chipfactory::mario)   [intra-org]
  #2  Mario Bianchi (acme::mario)          [cross-org]
  #3  Mariano Verdi (chipfactory::mariano) [intra-org]
→ pick one with contact('#1'), contact('#2'), …

> contact #2
Active peer: Mario Bianchi (acme::mario).
```

**Read your inbox and reply in thread:**
```
> receive_oneshot
1 one-shot message(s):
- [acme::alice] corr=4f12 reply_to=—: progetto pronto?

> reply sì, lo finisco oggi
Reply sent to acme::alice (threaded as reply to msg-…).
```

The intent-level tools (`contact`, `chat`, `reply`) wrap the lower-
level primitives (`send_oneshot`, `receive_oneshot`, `discover_agents`)
which remain exposed for power users and scripts. State is kept in
process memory only — no peer cache survives a server restart.

### Notifications

When you also keep `cullis-connector dashboard` running (typically via
`cullis-connector install-autostart`), it polls the local Mastio every
~10 seconds in the background and pops a **native OS notification**
(libnotify on Linux, NSUserNotification on macOS, Toast on Windows)
when a new message arrives. Click the notification to open
`http://127.0.0.1:7777/inbox`. Works regardless of whether your MCP
client (Claude Code, Cursor, …) is open — the dashboard process is
the one that owns the poll loop.

Tweaks via env on the dashboard process:

| Env var                              | Default | Effect                                             |
|--------------------------------------|---------|----------------------------------------------------|
| `CULLIS_CONNECTOR_NOTIFICATIONS=off` | `on`    | Disables the poller entirely (no popups, no badge) |
| `CULLIS_CONNECTOR_POLL_S=30`         | `10`    | Poll interval, in seconds                          |

Native notifications need the `dashboard` extra (which now pulls in
`plyer`):

```bash
pip install 'cullis-connector[dashboard]'
```

Headless boxes without a notification daemon fall back gracefully to
`stderr` — you'll see lines like `[cullis-notify] Message from
acme::mario: ciao!` in the dashboard log.

#### Statusline badge in Claude Code

The dashboard exposes `GET http://127.0.0.1:7777/status/inbox` which
returns the unread count + last sender. Both this endpoint and
`POST /status/inbox/seen` require a bearer token generated at first
dashboard start and persisted at
`~/.cullis/identity/statusline.token` (chmod 0600). The loopback bind
alone doesn't stop other local processes under your user, so the token
is what actually authenticates the statusline poller.

Drop this snippet into your `~/.claude/settings.json` to see
"📨 N from <sender>" in the Claude Code status bar:

```json
{
  "statusLine": {
    "type": "command",
    "command": "t=$(cat ~/.cullis/identity/statusline.token); s=$(curl -s -H \"Authorization: Bearer $t\" http://127.0.0.1:7777/status/inbox); u=$(echo $s | jq -r .unread); n=$(echo $s | jq -r .last_sender); [ \"$u\" != \"0\" ] && echo \"📨 $u from $n\" || true"
  }
}
```

When you've read the messages,
`curl -X POST -H "Authorization: Bearer $(cat ~/.cullis/identity/statusline.token)" http://127.0.0.1:7777/status/inbox/seen`
clears the counter (the dashboard's `/inbox` view does this
automatically on load).

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
