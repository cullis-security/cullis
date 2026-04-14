# Docker image for `cullis-connector`

Multi-stage image intended for MCP clients that launch connectors
as containers (ToolHive, Docker MCP gateway, custom orchestrators).

## Build (from monorepo root)

```bash
docker build -f packaging/docker/Dockerfile -t cullis-connector:dev .
```

## Smoke test

```bash
docker run --rm cullis-connector:dev --version
# → cullis-connector 0.1.0
```

## Enroll (one-off)

```bash
docker run --rm -it -v $HOME/.cullis:/home/cullis/.cullis \
  cullis-connector:dev enroll \
  --site-url https://cullis-site.acme.local \
  --requester-name "Alice Example" \
  --requester-email "alice@acme.example"
```

## Serve (MCP stdio)

Most MCP clients will exec the container on demand. Example for a
client that speaks stdio:

```json
{
  "mcpServers": {
    "cullis": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "${HOME}/.cullis:/home/cullis/.cullis",
        "ghcr.io/cullis-security/cullis-connector:latest",
        "serve", "--site-url", "https://cullis-site.acme.local"
      ]
    }
  }
}
```

## Published images

The release workflow publishes to GHCR on every `connector-v*` tag:

- `ghcr.io/cullis-security/cullis-connector:<version>`
- `ghcr.io/cullis-security/cullis-connector:latest`
