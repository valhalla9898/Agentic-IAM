"""Shared helpers for Streamlit Playwright E2E tests."""

import re
import os
from pathlib import Path


def ensure_artifacts_dir():
    artifacts_dir = Path("tests/e2e/artifacts")
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    return artifacts_dir


def save_artifacts(page, name_prefix):
    artifacts_dir = ensure_artifacts_dir()
    page.screenshot(path=str(artifacts_dir / f"{name_prefix}.png"))
    (artifacts_dir / f"{name_prefix}.html").write_text(page.content(), encoding="utf-8")


def login_as_admin(page):
    admin_username = os.getenv("AGENTIC_IAM_E2E_ADMIN_USERNAME", "admin")
    admin_password = os.getenv("AGENTIC_IAM_E2E_ADMIN_PASSWORD", "")

    if not admin_password:
        raise RuntimeError(
            "AGENTIC_IAM_E2E_ADMIN_PASSWORD is required for E2E login. "
            "Bootstrap an admin via setup_admin.py and export the password for test runs."
        )

    page.wait_for_selector('input[type="text"], input[type="password"]', timeout=10000)
    page.fill('input[type="text"]', admin_username)
    page.fill('input[type="password"]', admin_password)
    try:
        page.click("button:has-text('Login')")
    except Exception:
        page.keyboard.press("Enter")
    page.wait_for_load_state("networkidle")


def choose_selectbox_option(page, label_fragment, option_text):
    combobox = page.locator(f'input[aria-label*="{label_fragment}"]')
    combobox.click()
    try:
        page.locator('[role="option"]').first.wait_for(state="attached", timeout=1000)
    except Exception:
        combobox.press("Alt+ArrowDown")
        page.locator('[role="option"]').first.wait_for(state="attached", timeout=5000)
    page.get_by_role(
        "option",
        name=re.compile(
            f"^{re.escape(option_text)}$",
            re.IGNORECASE)).click()


def select_combobox_value(page, label_fragment, value):
    combobox = page.locator(f'input[aria-label*="{label_fragment}"]')
    combobox.focus()
    combobox.press("Control+A")
    combobox.fill(value)
    combobox.press("Enter")


def streamlit_base_url():
    return os.getenv("STREAMLIT_URL", "http://localhost:8501")
