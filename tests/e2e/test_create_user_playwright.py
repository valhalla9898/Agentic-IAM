import time
from uuid import uuid4

from playwright.sync_api import sync_playwright

from database import Database

from tests.e2e.helpers import (
    choose_selectbox_option,
    login_as_admin,
    save_artifacts,
    streamlit_base_url,
)


def test_create_user_flow():
    """Admin creates a user through the dashboard and the record is verified in the database."""
    base_url = streamlit_base_url()
    username = f"create_e2e_{uuid4().hex[:8]}"
    email = f"{username}@example.com"
    db = Database()

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            page.goto(base_url)
            login_as_admin(page)

            page.get_by_text("👥 User Management").click()
            page.wait_for_selector('text=Manage Users', timeout=10000)

            page.get_by_label("New username").fill(username)
            page.get_by_label("New email").fill(email)
            page.get_by_label("New password").fill("TestPass123!")
            choose_selectbox_option(page, "New role", "operator")
            page.get_by_role("button", name="➕ Create User").click()

            time.sleep(1)

            created_user = next((user for user in db.list_users() if user["username"] == username), None)
            assert created_user is not None
            assert created_user["email"] == email
            assert created_user["role"] == "operator"

            save_artifacts(page, "create_user_success")

            assert db.delete_user(created_user["id"]) is True
            assert db.get_user_by_id(created_user["id"]) is None
        except Exception:
            save_artifacts(page, "create_user_failure")
            raise
        finally:
            browser.close()
