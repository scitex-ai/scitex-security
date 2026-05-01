"""Entry point for `python -m scitex_security`."""

from scitex_security.cli import main

if __name__ == "__main__":
    raise SystemExit(main() or 0)
