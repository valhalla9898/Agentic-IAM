import os
import pytest

from playwright.sync_api import sync_playwright


def save_artifacts(page, name_prefix="create_user"):
    artifacts_dir = os.path.join("tests", "e2e", "artifacts")
    os.makedirs(artifacts_dir, exist_ok=True)
    page.screenshot(path=os.path.join(artifacts_dir, f"{name_prefix}.png"))
    html = page.content()
    with open(os.path.join(artifacts_dir, f"{name_prefix}.html"), "w", encoding="utf-8") as f:
        f.write(html)


def test_create_user_flow():
    """Basic scaffold for create-user E2E test. Fill selectors for your UI."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            page.goto("http://localhost:8501")
            # TODO: implement navigation to admin -> create user
            # Example (adjust selectors):
            # page.click("text=Login")
            # page.fill("input[name=username]", "admin")
            # page.fill("input[name=password]", "admin123")
            # page.click("button[type=submit]")

            # Placeholder assertion to show test runs
            assert "Agentic-IAM" in page.title()
            save_artifacts(page, "create_user_success")
        except Exception as e:
            save_artifacts(page, "create_user_failure")
            raise
        finally:
            browser.close()
