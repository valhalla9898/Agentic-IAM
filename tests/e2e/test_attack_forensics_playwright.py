from playwright.sync_api import sync_playwright

from tests.e2e.helpers import login_as_admin, save_artifacts, streamlit_base_url


def test_attack_forensics_demo_flow():
    base_url = streamlit_base_url()
    attack_url = f"{base_url}?page=%F0%9F%95%B5%EF%B8%8F%20Attack%20Forensics"

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            page.goto(attack_url)
            login_as_admin(page)

            page.wait_for_selector("text=🕵️ Attack Forensics", timeout=10000)
            page.wait_for_selector("text=Attack timeline", timeout=10000)

            page.get_by_role("button", name="Generate Demo Incident").click(force=True)
            page.wait_for_function(
                "document.body.innerText.includes('Attack Events') && document.body.innerText.includes('Blocked')",
                timeout=15000,
            )

            content = page.content().lower()
            assert "attack forensics" in content
            assert "attack events" in content
            assert "blocked" in content

            save_artifacts(page, "attack_forensics_success")

        except Exception:
            save_artifacts(page, "attack_forensics_failure")
            raise
        finally:
            browser.close()
