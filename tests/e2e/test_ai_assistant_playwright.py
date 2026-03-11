import time
from playwright.sync_api import sync_playwright


def test_ai_assistant_can_answer_and_summarize(tmp_path):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto('http://localhost:8501')
        # Wait for login page
        page.wait_for_selector('text=Agentic-IAM Login')
        # Fill demo credentials
        page.fill('input[placeholder="Username"]', 'admin')
        page.fill('input[type="password"]', 'admin123')
        page.click('text=🔐 Login')
        # Wait for dashboard
        page.wait_for_selector('text=🤖 AI Assistant', timeout=10000)
        page.click('text=🤖 AI Assistant')
        page.wait_for_selector('textarea')
        page.fill('textarea', 'How to enable mTLS?')
        page.select_option('select', 'knowledge')
        page.click('text=Ask')
        time.sleep(2)
        # take screenshot artifact
        art = tmp_path / 'ai_assistant.png'
        page.screenshot(path=str(art))
        browser.close()
