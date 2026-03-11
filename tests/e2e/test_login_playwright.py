"""Playwright E2E test for the Streamlit login flow.

Requires: `playwright` Python package and browsers installed (`playwright install`).

Run with: `pytest tests/e2e/test_login_playwright.py` (ensure Streamlit is running on :8501)
"""
import os
import time
import pytest
from pathlib import Path

from playwright.sync_api import sync_playwright


def _ensure_artifacts_dir():
    d = Path("tests/e2e/artifacts")
    d.mkdir(parents=True, exist_ok=True)
    return d


def test_login_flow():
    base_url = os.getenv("STREAMLIT_URL", "http://localhost:8501")
    artifacts = _ensure_artifacts_dir()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            page.goto(base_url)

            # Wait for login form elements
            page.wait_for_selector("input[type=\"text\"], input[type=\"password\"]", timeout=10000)

            # Fill credentials (default test creds)
            page.fill('input[type="text"]', 'admin')
            page.fill('input[type="password"]', 'admin123')

            # Click login button - try multiple selectors for robustness
            try:
                page.click("button:has-text('Login')")
            except Exception:
                page.keyboard.press("Enter")

            # allow redirect and dashboard render
            time.sleep(2)

            # Expect to see admin dashboard indicator
            content = page.content()
            Path(artifacts / "login_page.html").write_text(content, encoding="utf-8")
            page.screenshot(path=str(artifacts / "login_screenshot.png"))

            assert "admin" in content.lower()

        except Exception as e:
            # Capture diagnostics
            try:
                page.screenshot(path=str(artifacts / "login_failure.png"))
                Path(artifacts / "login_error.txt").write_text(str(e), encoding="utf-8")
                Path(artifacts / "page_content_on_failure.html").write_text(page.content(), encoding="utf-8")
            except Exception:
                pass
            raise
        finally:
            browser.close()
