"""Unified local quality gate for lint, smoke, and focused E2E checks."""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import List


@dataclass
class CheckResult:
    name: str
    command: List[str]
    exit_code: int
    duration_sec: float


def _run_check(name: str, command: List[str]) -> CheckResult:
    print(f"\n=== {name} ===")
    print("$ " + " ".join(command))
    start = time.time()
    proc = subprocess.run(command, check=False)
    duration = time.time() - start
    status = "PASS" if proc.returncode == 0 else "FAIL"
    print(f"[{status}] {name} ({duration:.2f}s)")
    return CheckResult(name=name, command=command, exit_code=proc.returncode, duration_sec=duration)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run local quality checks.")
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Skip E2E checks and run only lint + smoke tests.",
    )
    parser.add_argument(
        "--refresh-lock",
        action="store_true",
        help="Regenerate requirements-lock.txt before running checks.",
    )
    args = parser.parse_args()

    checks: List[tuple[str, List[str]]] = [
        (
            "flake8-core",
            [sys.executable, "-m", "flake8", "app.py", "run_gui.py"],
        ),
        (
            "flake8-ai",
            [
                sys.executable,
                "-m",
                "flake8",
                "dashboard/components/ai_assistant.py",
                "dashboard/components/ai_kb.py",
                "scripts/ask_ai.py",
                "tests/test_unit/test_ai_cli.py",
            ],
        ),
        (
            "ai-cli-smoke-tests",
            [sys.executable, "-m", "pytest", "tests/test_unit/test_ai_cli.py", "-q", "-o", "addopts="],
        ),
    ]

    if not args.quick:
        checks.append(
            (
                "focused-e2e",
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "tests/e2e/test_ai_assistant_playwright.py",
                    "tests/e2e/test_create_user_playwright.py",
                    "tests/e2e/test_admin_user_crud_playwright.py",
                    "tests/e2e/test_risk_assessment_playwright.py",
                    "-q",
                ],
            )
        )

    results: List[CheckResult] = []

    if args.refresh_lock:
        lock_result = _run_check("refresh-lockfile", [sys.executable, "scripts/update_lockfile.py"])
        results.append(lock_result)
        if lock_result.exit_code != 0:
            print("\nLockfile refresh failed. Stopping checks.")
            return 1

    results.extend(_run_check(name, command) for name, command in checks)

    failed = [r for r in results if r.exit_code != 0]
    print("\n=== Summary ===")
    for result in results:
        status = "PASS" if result.exit_code == 0 else "FAIL"
        print(f"- {status}: {result.name} ({result.duration_sec:.2f}s)")

    if failed:
        print(f"\n{len(failed)} check(s) failed.")
        return 1

    print("\nAll checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
