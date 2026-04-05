"""Shared helpers for Streamlit Playwright E2E tests."""

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
    page.wait_for_selector('input[type="text"], input[type="password"]', timeout=10000)
    page.fill('input[type="text"]', 'admin')
    page.fill('input[type="password"]', 'admin123')
    try:
        page.click("button:has-text('Login')")
    except Exception:
        page.keyboard.press("Enter")
    page.wait_for_load_state("networkidle")


def choose_selectbox_option(page, label_fragment, option_text):
    combobox = page.locator(f'input[aria-label*="{label_fragment}"]')
    combobox.click()
    page.get_by_role("option", name=option_text).click()


def select_combobox_value(page, label_fragment, value):
    combobox = page.locator(f'input[aria-label*="{label_fragment}"]')
    combobox.focus()
    combobox.press("Control+A")
    combobox.fill(value)
    combobox.press("Enter")


def streamlit_base_url():
    return os.getenv("STREAMLIT_URL", "http://localhost:8501")
