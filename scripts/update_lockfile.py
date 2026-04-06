"""Regenerate requirements-lock.txt from the active environment."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    lockfile = repo_root / "requirements-lock.txt"

    result = subprocess.run(
        [sys.executable, "-m", "pip", "freeze"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        print("Failed to generate lockfile:")
        print(result.stderr.strip())
        return result.returncode

    lockfile.write_text(result.stdout, encoding="utf-8")
    print(f"Updated {lockfile.name} ({len(result.stdout.splitlines())} packages)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
