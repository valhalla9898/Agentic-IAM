import os
import pytest

from playwright.sync_api import sync_playwright


def save_artifacts(page, name_prefix="register_agent"):
    artifacts_dir = os.path.join("tests", "e2e", "artifacts")
    os.makedirs(artifacts_dir, exist_ok=True)
    page.screenshot(path=os.path.join(artifacts_dir, f"{name_prefix}.png"))
    html = page.content()
    with open(os.path.join(artifacts_dir, f"{name_prefix}.html"), "w", encoding="utf-8") as f:
        f.write(html)


def test_register_agent_flow():
    """Basic scaffold for register-agent E2E test. Fill selectors for your UI."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            page.goto("http://localhost:8501")
            # TODO: implement navigation to agents -> register
            assert "Agentic-IAM" in page.title()
            save_artifacts(page, "register_agent_success")
        except Exception:
            save_artifacts(page, "register_agent_failure")
            raise
        finally:
            browser.close()
