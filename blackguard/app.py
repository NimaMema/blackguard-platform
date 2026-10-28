"""Compatibility entry point: ``python3 app.py`` behaves like ``python3 start.py``."""

from start import main

if __name__ == "__main__":
    raise SystemExit(main() or 0)
