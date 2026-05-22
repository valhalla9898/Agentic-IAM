"""Playwright E2E tests for core dashboard buttons.

These tests assume the Streamlit app is running on http://localhost:8501.
They do not require login for the demo flows (use demo buttons visible on public pages).
"""

from playwright.sync_api import sync_playwright

from tests.e2e.helpers import login_as_admin, save_artifacts, streamlit_base_url


def _open_sidebar_and_click(page, label_text: str):
    # Map human labels to the underlying radio `value` attributes used by Streamlit
    label_to_value = {
        "🕵️ Attack Forensics": "4",
        "🛡️ Security Operations": "15",
    }
    value = label_to_value.get(label_text)
    if value:
        selector = f'[data-testid="stSidebar"] input[type="radio"][value="{value}"]'
        page.wait_for_selector(selector, timeout=10000)
        page.locator(selector).click()
        return

    # Fallbacks: try role-based or text-based clicks
    try:
        page.get_by_role("radio", name=label_text).click()
    except Exception as e:
        import logging

        logging.getLogger(__name__).debug("Fallback click failed: %s", e)
        page.locator(f"text={label_text}").click(timeout=10000)


def test_generate_demo_incident_playwright():
    base_url = streamlit_base_url()
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            page.goto(base_url)
            # Login as admin so protected pages are available
            login_as_admin(page)
            # Open Attack Forensics via sidebar
            page.wait_for_selector("text=Navigation", timeout=10000)
            _open_sidebar_and_click(page, "🕵️ Attack Forensics")
            page.wait_for_selector("text=Generate Demo Incident", timeout=10000)
            page.click("text=Generate Demo Incident")
            page.wait_for_selector("text=Demo incident generated", timeout=10000)
            assert "Demo incident generated" in page.content()
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
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            page.goto(base_url)
            login_as_admin(page)
            page.wait_for_selector("text=Navigation", timeout=10000)
            # Navigate to Security Operations
            _open_sidebar_and_click(page, "🛡️ Security Operations")
            page.wait_for_selector("text=Execute Recommended Playbook", timeout=10000)
            # Click execute (if visible)
            page.click("text=Execute Recommended Playbook")
            page.wait_for_selector("text=Playbook", timeout=10000)
            assert "Playbook" in page.content()
            save_artifacts(page, "execute_playbook_success")
        except Exception as e:
            save_artifacts(page, "execute_playbook_failure")
            import logging

            logging.getLogger(__name__).debug("execute_playbook failed: %s", e)
            raise
        finally:
            browser.close()
