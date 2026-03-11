"""Playwright E2E test for the Streamlit login flow.

Requires: `playwright` Python package and browsers installed (`playwright install`).

Run with: `pytest tests/e2e/test_login_playwright.py` (ensure Streamlit is running on :8501)
"""
import os
import time
import pytest

from playwright.sync_api import sync_playwright


@pytest.mark.skipif(os.getenv("CI") == "true", reason="Run locally with browsers installed")
def test_login_flow():
    base_url = os.getenv("STREAMLIT_URL", "http://localhost:8501")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
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
        assert "admin" in page.content().lower()

        browser.close()
