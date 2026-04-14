# Standalone `cullis-connector` PyPI build

This directory contains a dedicated `pyproject.toml` that builds the
`cullis-connector` package as a **standalone distribution** on PyPI —
separate from the monorepo `cullis-agent-sdk` wheel.

## Why

The connector is the user-facing binary (runs inside Claude Code, Cursor,
Claude Desktop, ToolHive). Users installing it should not have to pull in
the full server-side SDK or pick through monorepo packaging. A separate
distribution also gives the connector its own:

- Versioning cadence (semver independent of broker/proxy releases)
- Branding on PyPI (`pip install cullis-connector`)
- Entry point in Docker MCP catalog & ToolHive registry

## Build locally

From the monorepo root:

```bash
python -m pip install --upgrade build
python -m build --outdir dist/ packaging/pypi
```

This produces:

- `dist/cullis_connector-<version>-py3-none-any.whl`
- `dist/cullis_connector-<version>.tar.gz`

## Smoke test the wheel

```bash
python -m venv /tmp/cc-smoke && . /tmp/cc-smoke/bin/activate
pip install dist/cullis_connector-*.whl
cullis-connector --version
deactivate
```

## Publish (maintainers only)

The release workflow (`.github/workflows/release-connector.yml`) handles
PyPI upload on tag `connector-v*`. A PyPI API token named `PYPI_TOKEN`
must be configured in the repo secrets before the first real publish.

See [`packaging/RELEASING.md`](../RELEASING.md) for the full checklist.
