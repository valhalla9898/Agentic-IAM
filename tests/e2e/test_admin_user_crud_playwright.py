"""Playwright E2E test for admin user CRUD in the Streamlit dashboard."""

import time
from uuid import uuid4

from playwright.sync_api import sync_playwright

from database import Database

from tests.e2e.helpers import (
    ensure_artifacts_dir,
    login_as_admin,
    choose_selectbox_option,
    select_combobox_value,
    streamlit_base_url,
)


def test_admin_user_crud_flow():
    base_url = streamlit_base_url()
    artifacts = ensure_artifacts_dir()
    username = f"e2e_admin_{uuid4().hex[:8]}"
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
            page.get_by_role("button", name="➕ Create User").click()

            time.sleep(1)
            created_user = next((user for user in db.list_users() if user["username"] == username), None)
            assert created_user is not None
            select_combobox_value(page, "Select user", f"{username} ({email})")
            choose_selectbox_option(page, "Edit role", "operator")
            choose_selectbox_option(page, "Edit status", "suspended")
            page.get_by_role("button", name="💾 Save User Changes").click()

            time.sleep(1)
            updated_user = db.get_user_by_id(created_user["id"])
            assert updated_user is not None
            assert updated_user["role"] == "operator"
            assert updated_user["status"] == "suspended"

            page.get_by_role("button", name=f"Delete {username}").click()
            time.sleep(1)

            deleted_user = db.get_user_by_id(created_user["id"])
            assert deleted_user is None
            assert all(user["username"] != username for user in db.list_users())

            page.screenshot(path=str(artifacts / "admin_user_crud_success.png"))
            (artifacts / "admin_user_crud_success.html").write_text(page.content(), encoding="utf-8")
        except Exception:
            page.screenshot(path=str(artifacts / "admin_user_crud_failure.png"))
            (artifacts / "admin_user_crud_failure.html").write_text(page.content(), encoding="utf-8")
            raise
        finally:
            browser.close()
