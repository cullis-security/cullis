# Contributing to Cullis

Thank you for your interest in contributing to Cullis! This guide will help you get started.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/cullis-security/cullis.git
cd cullis

# Create virtual environment
python3.11 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run tests
pytest tests/ -v

# Full broker deployment (Docker + PKI + Vault) — development profile
./deploy_broker.sh --dev

# Or boot the entire scripted demo (broker + 2 proxies + 2 agents):
./deploy_demo.sh up
python scripts/demo/sender.py
```

## Frontend Assets (Dashboard)

The broker and proxy dashboards ship compiled Tailwind CSS and a bundled copy
of htmx — no CDN dependency. Generated CSS is `.gitignore`'d; you need to
build it once before running the broker outside Docker:

```bash
# Uses the Tailwind standalone CLI (no Node/npm install required).
./scripts/build_frontend.sh
# or with watch mode while iterating on templates:
./scripts/build_frontend.sh --watch
```

The Docker images (`Dockerfile`, `mcp_proxy/Dockerfile`) run the build in a
dedicated stage, so `./deploy_broker.sh`, `./deploy_demo.sh`, and
`./deploy_proxy.sh` already produce the CSS automatically.

Templates should rely on Tailwind utility classes only — inline `tailwind.config = {...}`
blocks are not supported anymore (they required the runtime CDN build).
Update `tailwind.config.js` at the repo root if you need new theme tokens.

## Code Conventions

- **Async:** All DB and HTTP code uses async/await
- **Type hints:** Required on all public functions
- **Pydantic:** Every endpoint uses Pydantic schemas for request/response
- **Logging:** Use `logging` module, never `print`
- **Tests:** Every new feature requires tests in `tests/`

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes following the code conventions above
4. Add tests for any new functionality
5. Ensure all tests pass: `pytest tests/ -v`
6. Commit with a clear message describing the change
7. Push to your fork and open a Pull Request

## PR Checklist

Before submitting, verify:

- [ ] All tests pass (`pytest tests/ -v`)
- [ ] Type hints added to public functions
- [ ] No secrets, private keys, or credentials in the code
- [ ] New endpoints have Pydantic schemas

## What to Contribute

Check out issues labeled [`good-first-issue`](https://github.com/cullis-security/cullis/labels/good-first-issue) and [`help-wanted`](https://github.com/cullis-security/cullis/labels/help-wanted).

Areas where contributions are especially welcome:
- **SDKs:** TypeScript, Go, Java client libraries
- **Documentation:** Tutorials, deployment guides, API docs
- **Dashboard:** UI improvements, new views
- **Deployment:** Helm charts, Terraform modules, docker-compose variants
- **Tests:** Additional test coverage

## Security Issues

**Do not open a public issue for security vulnerabilities.** Email
[security@cullis.io](mailto:security@cullis.io) directly, or use GitHub's
private vulnerability reporting. See [SECURITY.md](SECURITY.md) for the full
disclosure policy.

## Questions?

- General questions: email [hello@cullis.io](mailto:hello@cullis.io) or open a [GitHub Discussion](https://github.com/cullis-security/cullis/discussions) in the Q&A category.
- Security questions: [security@cullis.io](mailto:security@cullis.io) (do not post in public).

## License

Cullis uses a split licensing model. By contributing, you agree that your contribution is licensed under the same terms as the component you are modifying:

- Contributions to `app/` or `mcp_proxy/` are licensed under [FSL-1.1-Apache-2.0](LICENSE).
- Contributions to `cullis_sdk/` or `enterprise-kit/` are licensed under the [Apache License 2.0](cullis_sdk/LICENSE).
- Contributions to `sdk-ts/` are licensed under the [MIT License](sdk-ts/LICENSE).

See [NOTICE](NOTICE) for the full component-by-component map.

## Developer Certificate of Origin (DCO)

Every commit must be signed off to certify that you have the right to submit it under the applicable license. This is a lightweight alternative to a formal CLA, used by the Linux kernel and many other projects.

Add the sign-off automatically with:

```bash
git commit -s -m "Your commit message"
```

This appends a line like `Signed-off-by: Your Name <you@example.com>` to your commit message. The full text of the DCO is at [developercertificate.org](https://developercertificate.org/).

Pull requests whose commits are not signed off will be asked to amend and re-push.
