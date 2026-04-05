"""Playwright E2E test for the Streamlit login flow.

Requires: `playwright` Python package and browsers installed (`playwright install`).

Run with: `pytest tests/e2e/test_login_playwright.py` (ensure Streamlit is running on :8501)
"""

from playwright.sync_api import sync_playwright

from tests.e2e.helpers import login_as_admin, save_artifacts, streamlit_base_url


def test_login_flow():
    base_url = streamlit_base_url()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            page.goto(base_url)
            login_as_admin(page)

            page.wait_for_selector('text=Navigation', timeout=10000)
            page.wait_for_selector('text=👥 User Management', timeout=10000)
            page.get_by_text("👥 User Management").click()
            page.wait_for_selector('text=Manage Users', timeout=10000)

            assert "user management" in page.content().lower()
            assert "manage users" in page.content().lower()

            save_artifacts(page, "login_success")

        except Exception:
            save_artifacts(page, "login_failure")
            raise
        finally:
            browser.close()
