"""Allow ``python -m autopsy`` to invoke the CLI."""
from autopsy.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
