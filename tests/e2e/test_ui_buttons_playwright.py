"""Playwright E2E tests for core dashboard buttons.

These tests assume the Streamlit app is running on http://localhost:8501.
They do not require login for the demo flows (use demo buttons visible on public pages).
"""

from playwright.sync_api import sync_playwright

from tests.e2e.helpers import login_as_admin, save_artifacts, streamlit_base_url


def test_generate_demo_incident_playwright():
    base_url = streamlit_base_url()
    attack_url = f"{base_url}?page=%F0%9F%95%B5%EF%B8%8F%20Attack%20Forensics"
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            page.goto(attack_url)
            # Login as admin so protected pages are available
            login_as_admin(page)
            page.wait_for_selector("text=Attack Forensics", timeout=10000)
            page.wait_for_selector("text=Generate Demo Incident", timeout=10000)
            page.get_by_role("button", name="Generate Demo Incident").click(force=True)
            page.wait_for_function(
                "document.body.innerText.includes('Attack Events') && document.body.innerText.includes('Blocked')",
                timeout=15000,
            )
            assert "Attack Events" in page.content()
            assert "Blocked" in page.content()
            save_artifacts(page, "generate_demo_incident_success")
        except Exception as e:
            save_artifacts(page, "generate_demo_incident_failure")
            import logging

            logging.getLogger(__name__).debug("generate_demo_incident failed: %s", e)
            raise
        finally:
            browser.close()


def test_execute_recommended_playbook_playwright():
    base_url = streamlit_base_url()
    security_ops_url = f"{base_url}?page=%F0%9F%9B%A1%EF%B8%8F%20Security%20Operations"
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            page.goto(security_ops_url)
            login_as_admin(page)
            page.wait_for_selector("text=Execute Recommended Playbook", timeout=10000)
            # Click execute (if visible)
            page.get_by_role("button", name="Execute Recommended Playbook").click(force=True)
            page.wait_for_function(
                "document.body.innerText.toLowerCase().includes('playbook')",
                timeout=15000,
            )
            assert "Playbook" in page.content()
            save_artifacts(page, "execute_playbook_success")
        except Exception as e:
            save_artifacts(page, "execute_playbook_failure")
            import logging

            logging.getLogger(__name__).debug("execute_playbook failed: %s", e)
            raise
        finally:
            browser.close()
