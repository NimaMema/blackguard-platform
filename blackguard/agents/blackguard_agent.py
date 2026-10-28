"""BLACKGUARD agent launcher: ``python3 agents/blackguard_agent.py --help``."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bgagent.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
