#!/usr/bin/env python3
"""
Thin repo-root wrapper so the CLI can be invoked exactly as:

    python scan.py --target http://localhost:8000/agent --adapter langchain
    python scan.py --target http://localhost:8001/agent --adapter native

The same logic is also installed as the `talos-scan` console script (see
pyproject.toml) once the package is pip-installed.
"""
import sys

from talos.cli import main

if __name__ == "__main__":
    sys.exit(main())
