"""Allow ``python -m cullis_connector`` invocation."""
from cullis_connector.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
