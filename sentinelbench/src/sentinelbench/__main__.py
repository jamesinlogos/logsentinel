"""``python -m sentinelbench`` entry point."""

from __future__ import annotations

import sys

from sentinelbench.cli import main

if __name__ == "__main__":
    sys.exit(main())
