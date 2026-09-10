"""Entry point so the tool can run as ``python -m netsniff``."""

from netsniff.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
