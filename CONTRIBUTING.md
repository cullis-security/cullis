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

**Do not open a public issue for security vulnerabilities.** Please see [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## Questions?

Open a [GitHub Discussion](https://github.com/cullis-security/cullis/discussions) in the Q&A category.

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
